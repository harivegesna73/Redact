#src/redactor.py
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from faker import Faker
import re


class PIIRedactor:
    def __init__(self, custom_deny_list=None, target_entities=None):
        self.pii_engine = AnalyzerEngine()
        self.synthetic_gen = Faker('en_IN')

        # Unified identity registry: canonical_key -> fake replacement.
        # Keeping this alive across calls to redact_text() is what makes the
        # same real person / company map to the same fake value everywhere.
        self.alias_vault = {}

        default_allow_list = {
            "company", "our company", "the company", "board", "directors",
            "board of directors", "promoter", "promoters", "promoter group",
            "promoter selling shareholders", "selling shareholders", "shareholders",
            "bidder", "bidders", "first bidder", "anchor investor", "anchor investors",
            "qib", "qibs", "riis", "nii", "niis", "mutual funds", "investors",
            "registrar", "registrar to the offer", "book running lead managers", "brlms",
            "syndicate", "syndicate members", "auditors", "statutory auditors",
            "stock exchanges", "bse", "nse", "roc", "sebi", "rbi",
            "government of india", "state government", "central government",
            "maharashtra sales tax department", "ministry of commerce and industry",
            "india", "maharashtra", "pune", "mumbai",
            "red herring prospectus", "prospectus", "equity shares", "pan",
            "dp id", "upi id", "order", "ticket", "rupees", "inr",
            "scsb", "scsbs", "companies act",
        }

        # BUG FIX: the previous version did
        #   self.ignore_set = set(custom_deny_list or default_allow_list)
        # which means passing a custom_deny_list *replaced* the safe defaults
        # instead of adding to them. That's what caused "India", "Anchor
        # Investors", "Maharashtra Sales Tax Department", "Auditors", etc. to
        # start getting redacted again once main.py supplied its own list.
        # Always take the union of both.
        merged = set(w.lower() for w in default_allow_list)
        if custom_deny_list:
            merged |= set(w.lower() for w in custom_deny_list)
        self.ignore_set = merged

        # Precise Corporate Pattern Matcher
        # BUG FIX: the original regex used `[a-zA-Z0-9&.\-]` (digits allowed
        # in every token) and `\s*` between tokens (which matches newlines).
        # Combined, that let the pattern reach *backward across a line
        # break* and swallow an unrelated preceding token -- e.g. on:
        #     SEBI Registration Number: INM000013004
        #     Nuvama Wealth Management Limited
        # it matched "INM000013004\nNuvama Wealth Management Limited" as a
        # single organization span. That merged span then fell inside the
        # law/regulatory context filter (which saw "Registration Number" in
        # its window) and got discarded entirely -- taking the real,
        # legitimate company name down with it. This wasn't a rare edge
        # case: it's exactly why "Nuvama Wealth Management Limited" leaked
        # even though it has the "Limited" suffix corp_recog is designed to
        # catch.
        #
        # Separately, the old pattern required every token to start with
        # `[A-Z]`, so "Kirtane & Pandit LLP" only matched "Pandit LLP" --
        # the bare "&" broke the repeated-token group, leaving "Kirtane"
        # sitting outside the match and unredacted.
        #
        # Fix: (1) drop digits from the per-token character class so
        # alphanumeric codes can't be absorbed as a "word" of the company
        # name, (2) restrict inter-token whitespace to `[ \t]*` so the
        # match can't cross a line break, (3) allow a bare `&` as its own
        # token, and (4) allow an optional trailing comma before the legal
        # suffix (e.g. "Kirtane & Pandit, LLP").
        corp_pattern = Pattern(
            name="ind_corp",
            regex=r"\b((?:[A-Z][a-zA-Z&.\-]*|&)[ \t]*){1,8},?\s*(?:Private Limited|Limited|LLP|Pvt\. Ltd\.|Ltd\.)\b",
            score=0.95
        )
        corp_recog = PatternRecognizer(supported_entity="ORGANIZATION", patterns=[corp_pattern])
        self.pii_engine.registry.add_recognizer(corp_recog)

        # REAL BUG FIX: Presidio's default nlp engine config
        # (presidio_analyzer/conf/spacy.yaml) hard-codes ORG/ORGANIZATION
        # into `ner_model_configuration.labels_to_ignore`, with an inline
        # comment noting "has many false positives". That filtering happens
        # inside SpacyNlpEngine, *before* entities are even mapped to
        # Presidio entity names or handed to any recognizer -- it's a
        # different, earlier stage than SpacyRecognizer.supported_entities.
        #
        # A previous attempt at this fix only touched
        # SpacyRecognizer.supported_entities, which was already a no-op:
        # spaCy's model was correctly tagging "Nuvama", "Kirtane", and
        # "Trilegal" as ORG the whole time, but the NLP engine discarded
        # those detections before the recognizer ever saw them, regardless
        # of what supported_entities said. That's why toggling it produced
        # identical leak counts on re-run.
        #
        # The actual fix has to happen at the NLP-engine layer: remove
        # ORG/ORGANIZATION from labels_to_ignore so spaCy's NER can act as a
        # second-chance recognizer alongside corp_recog for company names
        # that appear without a "Limited/LLP/Pvt. Ltd." suffix in a given
        # mention (e.g. a table cell that just says "Nuvama").
        self._enable_spacy_organization_detection()

        # Also restrict LOCATION on the SpacyRecognizer itself -- it's still
        # too noisy/low-precision for our purposes and over-fires on
        # street/city names inside address blocks that our dedicated
        # ADDRESS recognizer already owns.
        self._restrict_to_high_precision_recognizers()

        # Precise DOB Matcher
        birth_pattern = Pattern(
            name="birth_regex",
            regex=r"(?i)(?:DOB|Date of Birth)\s*[:-]?\s*([0-9]{1,4}[/\-][0-9]{1,2}[/\-][0-9]{1,4})",
            score=0.95
        )
        birth_recog = PatternRecognizer(supported_entity="DOB", patterns=[birth_pattern])
        self.pii_engine.registry.add_recognizer(birth_recog)

        # Spaced & International Phone Matcher
        ind_phone_pattern = Pattern(
            name="ind_phone",
            regex=r"(\+91[\-\s]?)?[0-9]{2,4}[\-\s]?[0-9]{3,4}[\-\s]?[0-9]{3,4}",
            score=0.95
        )
        phone_recog = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[ind_phone_pattern])
        self.pii_engine.registry.add_recognizer(phone_recog)

        # SEBI / regulatory registration numbers are business identifiers,
        # not PII, but their format (e.g. INM000013004, INR000004058) can
        # get swept up by generic entity/word matching if nothing recognizes
        # them explicitly. Recognizing them lets the context filter reliably
        # route them to "ignore" instead of relying on substring checks
        # against text that may not include the label.
        reg_number_pattern = Pattern(
            name="sebi_reg_no",
            regex=r"\bIN[A-Z]\d{9}\b",
            score=0.9
        )
        reg_number_recog = PatternRecognizer(supported_entity="REG_NUMBER", patterns=[reg_number_pattern])
        self.pii_engine.registry.add_recognizer(reg_number_recog)

        # Dedicated multi-line Indian mailing-address block matcher.
        # Relying on generic LOCATION/PERSON NER against dense,
        # comma-separated address blocks is what caused addresses to get
        # shredded into 5-10 separately-faked fragments. This pattern looks
        # for a line ending in a 6-digit PIN code, optionally preceded by a
        # state name, and treats the whole thing as one address entity.
        address_pattern = Pattern(
            name="ind_address_block",
            regex=r"[A-Za-z0-9,.\-/()\s]{10,120}?\b\d{6}\b",
            score=0.6
        )
        address_recog = PatternRecognizer(supported_entity="ADDRESS", patterns=[address_pattern])
        self.pii_engine.registry.add_recognizer(address_recog)

        self.active_targets = target_entities if target_entities else [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "ADDRESS",
            "US_SSN", "CREDIT_CARD", "IP_ADDRESS", "ORGANIZATION", "DOB",
            "REG_NUMBER",
        ]

        # Per-entity confidence floors. Structured/regex-based entities can
        # keep a low, precise threshold. Free-text NLP-based entities
        # (PERSON, ORGANIZATION) need a higher bar or they start flagging
        # street names, role titles, and fragments of legal boilerplate.
        self.entity_thresholds = {
            "PERSON": 0.6,
            "ORGANIZATION": 0.6,
            "EMAIL_ADDRESS": 0.4,
            "PHONE_NUMBER": 0.4,
            "ADDRESS": 0.4,
            "DOB": 0.4,
            "REG_NUMBER": 0.4,
            "US_SSN": 0.4,
            "CREDIT_CARD": 0.4,
            "IP_ADDRESS": 0.4,
        }

    def _enable_spacy_organization_detection(self):
        """Remove ORG/ORGANIZATION from the underlying spaCy NLP engine's
        labels_to_ignore. Presidio's default config filters these out at
        the NLP-engine layer (before any recognizer runs) specifically
        because bare organization NER "has many false positives" -- so
        re-enabling this trades some precision for the recall we need to
        catch company names with no legal suffix (see the corp_recog regex
        below, which only matches names ending in Private Limited/Limited/
        LLP/Pvt. Ltd./Ltd.). The ignore_set and context-window filtering in
        redact_text() are what keep that precision loss in check -- expect
        to keep tuning ignore_set as new false positives show up."""
        try:
            ner_config = self.pii_engine.nlp_engine.ner_model_configuration
            ner_config.labels_to_ignore = [
                label for label in ner_config.labels_to_ignore
                if label not in ("ORG", "ORGANIZATION")
            ]
        except Exception:
            # If Presidio's nlp_engine/ner_model_configuration API shifts
            # across versions, fail open rather than crash the pipeline.
            pass

        # BUG FIX: the previous version of this file only ever *removed*
        # "LOCATION" from SpacyRecognizer.supported_entities. It never
        # checked what was actually in that list to begin with. Presidio's
        # own registry-construction step builds SpacyRecognizer with
        # ORGANIZATION already excluded (based on the default
        # labels_to_ignore, at construction time) -- so the live list was
        # ['LOCATION', 'NRP', 'DATE_TIME', 'PERSON'], no ORGANIZATION at
        # all. Filtering out "LOCATION" from a list that never had
        # "ORGANIZATION" in it changes nothing. Clearing labels_to_ignore
        # above only fixes the *runtime* filter in SpacyNlpEngine; the
        # recognizer's supported_entities list was fixed at construction
        # time and needs to be explicitly patched here too.
        try:
            for recognizer in self.pii_engine.registry.recognizers:
                if recognizer.name == "SpacyRecognizer":
                    if "ORGANIZATION" not in recognizer.supported_entities:
                        recognizer.supported_entities = list(
                            recognizer.supported_entities
                        ) + ["ORGANIZATION"]
        except Exception:
            pass

    def _restrict_to_high_precision_recognizers(self):
        """Limit spaCy's generic NLP-based recognizer so it doesn't
        conflict with our custom regex recognizers where we have a
        precise, dedicated recognizer already (LOCATION is fully owned by
        our ADDRESS pattern recognizer). ORGANIZATION is intentionally left
        enabled on spaCy: it's our only fallback for company names that
        appear without a legal-entity suffix (e.g. a bare "Nuvama" in a
        table cell), and alias consistency across recognizers is already
        handled by canonicalization + substring matching in
        _to_canonical_key()/_resolve_alias()."""
        try:
            registry = self.pii_engine.registry
            for recognizer in list(registry.recognizers):
                if recognizer.name == "SpacyRecognizer":
                    recognizer.supported_entities = [
                        e for e in recognizer.supported_entities
                        if e not in ("LOCATION",)
                    ]
        except Exception:
            # Presidio's registry API has shifted across versions; fail open
            # rather than crash the whole pipeline if introspection fails.
            pass

    def _to_canonical_key(self, raw_text: str) -> str:
        """Transforms variants like 'KSH International Limited', 'the KSH
        International', 'our KSH International' into a single root key so
        they all resolve to the same fake alias."""
        text = raw_text.lower().strip()
        text = re.sub(r"^(the|our|its)\s+(company\s+)?", "", text)
        text = re.sub(
            r"\b(private limited|limited|pvt\.?\s*ltd\.?|ltd\.?|llp|inc|corp|co|group|llc)\b",
            "", text
        )
        text = re.sub(r"[^\w\s]", "", text)
        return re.sub(r"\s+", " ", text).strip()

    def _resolve_alias(self, canonical: str, entity_type: str) -> str:
        """Look up (or create) a fake replacement for a canonical key. Also
        checks whether this key is a substring/superset of an existing vault
        entry (e.g. 'ksh international' vs 'ksh international limited'
        both canonicalize the same way already, but this guards against
        near-miss variants from different recognizer spans) before minting a
        brand-new alias."""
        if canonical in self.alias_vault:
            return self.alias_vault[canonical]

        for existing_key, existing_alias in self.alias_vault.items():
            if not existing_key or not canonical:
                continue
            if existing_key in canonical or canonical in existing_key:
                self.alias_vault[canonical] = existing_alias
                return existing_alias

        new_alias = self._get_mock_data(entity_type)
        self.alias_vault[canonical] = new_alias
        return new_alias

    def _get_mock_data(self, label_type: str) -> str:
        if label_type == "PERSON":
            return self.synthetic_gen.name()
        elif label_type == "EMAIL_ADDRESS":
            return self.synthetic_gen.free_email()
        elif label_type == "PHONE_NUMBER":
            return self.synthetic_gen.phone_number()
        elif label_type in ("LOCATION", "ADDRESS"):
            return (
                f"{self.synthetic_gen.street_address()}, "
                f"{self.synthetic_gen.city()} - {self.synthetic_gen.postcode()}"
            )
        elif label_type == "ORGANIZATION":
            return self.synthetic_gen.company() + " Limited"
        elif label_type == "DOB":
            return self.synthetic_gen.date_of_birth().strftime("%d/%m/%Y")
        elif label_type == "US_SSN":
            return self.synthetic_gen.ssn()
        elif label_type == "CREDIT_CARD":
            return self.synthetic_gen.credit_card_number()
        elif label_type == "IP_ADDRESS":
            return self.synthetic_gen.ipv4()
        elif label_type == "REG_NUMBER":
            # Shouldn't normally be reached (REG_NUMBER is business data,
            # not PII, and gets routed to ignore in redact_text), but keep a
            # format-preserving fallback just in case.
            return "IN" + self.synthetic_gen.random_uppercase_letter() + \
                str(self.synthetic_gen.random_number(digits=9, fix_len=True))
        return self.synthetic_gen.word()

    def redact_text(self, source_text: str) -> str:
        if not source_text or not source_text.strip():
            return source_text

        raw_detections = self.pii_engine.analyze(
            text=source_text,
            entities=self.active_targets,
            language='en',
            score_threshold=0.4
        )

        # Apply per-entity thresholds (analyze() only supports one global
        # threshold, so filter afterward).
        raw_detections = [
            d for d in raw_detections
            if d.score >= self.entity_thresholds.get(d.entity_type, 0.4)
        ]

        # 1. Non-Maximum Suppression.
        # BUG FIX: previously sorted by span length only, which let a long,
        # low-confidence, wrong span (e.g. "Malvadkar Company Secretary")
        # beat a short, correct, high-confidence one. Sort by score first,
        # length as a tiebreaker.
        raw_detections = sorted(
            raw_detections, key=lambda x: (x.score, x.end - x.start), reverse=True
        )
        resolved_items = []

        for item in raw_detections:
            has_overlap = False
            for accepted in resolved_items:
                if not (item.end <= accepted.start or item.start >= accepted.end):
                    has_overlap = True
                    break
            if not has_overlap:
                resolved_items.append(item)

        # 2. Context Filter & Clean
        valid_items = []
        for item in resolved_items:
            extracted_string = source_text[item.start:item.end].strip()
            canonical = extracted_string.lower()

            clean_allow = re.sub(r"^the\s+", "", canonical)
            if clean_allow in self.ignore_set or canonical in self.ignore_set:
                continue

            # REG_NUMBER entities (SEBI/RBI style registration codes) are
            # business identifiers, not PII -- always skip them outright
            # rather than relying on nearby-word context matching.
            if item.entity_type == "REG_NUMBER":
                continue

            # Look at a window of text *around* the match, not just inside
            # it, since labels like "SEBI Registration Number:" usually sit
            # just before the code rather than inside the matched span.
            #
            # BUG FIX: this window used to be a flat 40-char lookback with
            # no regard for line breaks. On a table cell / multi-line block
            # like "SEBI Registration Number: INM000013004\nNuvama Wealth
            # Management Limited", a match starting right after the
            # newline (the company name) still had "registration number"
            # fall inside its 40-char window from the *previous* line,
            # causing a legitimate, unrelated organization match to be
            # discarded. Bound the lookback at the nearest preceding
            # newline so context from a different line/paragraph can't
            # bleed into this match's filter decision.
            newline_pos = source_text.rfind("\n", 0, item.start)
            window_start = newline_pos + 1 if newline_pos != -1 else max(0, item.start - 40)
            context_window = source_text[window_start:item.end].lower()
            if any(
                law_word in context_window
                for law_word in [" act", "rules", "regulations", "sebi registration", "registration number"]
            ):
                continue

            if len(extracted_string) <= 2:
                continue

            valid_items.append(item)

        # 3. Sort backwards by start index to safeguard alignment strings
        valid_items.sort(key=lambda x: x.start, reverse=True)
        final_output = source_text

        for item in valid_items:
            raw_string = final_output[item.start:item.end]
            root_key = self._to_canonical_key(raw_string)

            replacement_val = self._resolve_alias(root_key, item.entity_type)

            # Restore visual layout casing context
            if raw_string.isupper():
                replacement_val = replacement_val.upper()
            elif raw_string.istitle():
                replacement_val = replacement_val.title()

            final_output = final_output[:item.start] + replacement_val + final_output[item.end:]

        return final_output