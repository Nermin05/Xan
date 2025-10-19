import json
from django.core.management.base import BaseCommand
from hexaShiftApp.models import AttackLog, ClassifiedAttack, GeneratedRule
from hexaShiftApp.classifier import classify_log

class Command(BaseCommand):
    help = "Process unprocessed logs"

    def handle(self, *args, **options):
        qs = AttackLog.objects.filter(processed=False).order_by("received_at")[:100]
        for log in qs:
            res = classify_log(log.raw_text or json.dumps(log.raw_json))

            ca = ClassifiedAttack.objects.create(
                log=log,
                mitre_id=res["mitre_id"],
                attack_family=res["attack_family"],
                confidence=res["confidence"]
            )

            rule = {"id": ca.id, "mitre_id": res["mitre_id"], "desc": f"Auto rule for {res['attack_family']}"}
            GeneratedRule.objects.create(classified=ca, rule_text=json.dumps(rule))

            log.processed = True
            log.save()

            self.stdout.write(f"Processed log {log.id} -> {ca.attack_family}")
