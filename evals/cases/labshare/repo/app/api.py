import os
from flask import Flask, request, jsonify, g
from .auth import require_token, require_role
from .db import query
from .exports import enqueue_export

app = Flask(__name__)
LIMS_WEBHOOK_SECRET = os.environ.get("LIMS_WEBHOOK_SECRET", "")


@app.get("/api/results/<study_id>")
@require_token
def list_results(study_id):
    rows = query(
        "SELECT r.id, r.name FROM results r JOIN studies s ON s.id = r.study_id "
        "WHERE s.id = %s AND s.tenant_id = %s",
        (study_id, g.user["tenant_id"]),
    )
    return jsonify(rows)


@app.post("/api/export")
@require_token
@require_role("sponsor_scientist")
def export():
    body = request.get_json()
    tenant_id = body["tenant_id"]
    study_id = body["study_id"]
    job = enqueue_export(tenant_id=tenant_id, study_id=study_id, requested_by=g.user["sub"])
    return jsonify({"job": job}), 202


@app.post("/api/webhooks/lims")
def lims_webhook():
    event = request.get_json()
    query("UPDATE studies SET status = 'results_ready' WHERE id = %s", (event["study_id"],))
    return "", 204
