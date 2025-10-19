import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from .models import AttackLog, ClassifiedAttack, GeneratedRule
from .classifier import classify_log  
@csrf_exempt
def receive_log(request):
    """
    Honeypot serverdən gələn logları qəbul edir,
    dərhal DB-yə yazır və classify edib qaytarır.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)


    try:
        payload = json.loads(request.body)
    except Exception:
        return JsonResponse({"error": "Invalid JSON"}, status=400)


    src = payload.get("src_ip") or payload.get("source") or None
    raw_text = payload.get("message") or json.dumps(payload)

 
    log = AttackLog.objects.create(
        raw_json=payload,
        source_ip=src,
        raw_text=raw_text
    )

    result = classify_log(raw_text)

    ca = ClassifiedAttack.objects.create(
        log=log,
        mitre_id=result["mitre_id"],
        attack_family=result["attack_family"],
        confidence=result["confidence"]
    )

  
    GeneratedRule.objects.create(
        classified=ca,
        rule_text=json.dumps({
            "mitre_id": result["mitre_id"],
            "desc": f"Auto rule for {result['attack_family']}"
        })
    )

    log.processed = True
    log.save()

    return JsonResponse({
        "status": "ok",
        "log_id": log.id,
        "attack_family": result["attack_family"],
        "mitre_id": result["mitre_id"],
        "confidence": result["confidence"]
    }, status=201)


def dashboard(request):
    """
    Daoshbard-u göstərir: son loglar, events və generated rules
    """
    logs = AttackLog.objects.order_by('-received_at')[:50]
    events = ClassifiedAttack.objects.order_by('-detected_at')[:50]
    rules = GeneratedRule.objects.order_by('-created_at')[:50]

    return render(request, "dashboard.html", {  
        "logs": logs,
        "events": events,
        "rules": rules,
    })
