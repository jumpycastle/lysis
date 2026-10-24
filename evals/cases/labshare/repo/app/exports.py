import boto3
from .db import query

s3 = boto3.client("s3")
BUCKET = "labshare-results"


def enqueue_export(tenant_id, study_id, requested_by):
    files = query(
        "SELECT s3_key FROM results r JOIN studies s ON s.id = r.study_id "
        "WHERE s.id = %s AND s.tenant_id = %s",
        (study_id, tenant_id),
    )
    # zip + upload happens in the worker; return a 7-day link
    return s3.generate_presigned_url(
        "get_object", Params={"Bucket": BUCKET, "Key": f"exports/{study_id}.zip"}, ExpiresIn=604800
    )
