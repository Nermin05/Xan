from django.contrib import admin

from django.contrib import admin
from .models import AttackLog, ClassifiedAttack, GeneratedRule

admin.site.register(AttackLog)
admin.site.register(ClassifiedAttack)
admin.site.register(GeneratedRule)
