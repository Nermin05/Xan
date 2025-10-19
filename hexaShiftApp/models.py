from django.db import models

class AttackLog(models.Model):
    received_at = models.DateTimeField(auto_now_add=True)
    raw_json = models.JSONField()
    source_ip = models.CharField(max_length=45, blank=True, null=True)
    raw_text = models.TextField(blank=True, null=True)
    processed = models.BooleanField(default=False)

class ClassifiedAttack(models.Model):
    log = models.OneToOneField(AttackLog, on_delete=models.CASCADE, related_name="classification")
    mitre_id = models.CharField(max_length=50, null=True, blank=True)
    attack_family = models.CharField(max_length=200)
    confidence = models.FloatField(default=0.0)
    detected_at = models.DateTimeField(auto_now_add=True)

class GeneratedRule(models.Model):
    classified = models.ForeignKey(ClassifiedAttack, on_delete=models.CASCADE, related_name="rules")
    rule_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    active = models.BooleanField(default=True)
