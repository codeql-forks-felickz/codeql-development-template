import zipfile

import boto3


def lambda_handler(event, context):
    client = boto3.client("s3")
    y = int(event["year"])
    m = int(event["month"])
    zip_file = "{:04d}-{:02d}-receipts.zip".format(y, m)
    zf = zipfile.ZipFile("/tmp/" + zip_file, "w")
    zf.close()
    client.upload_file("/tmp/" + zip_file, "receipts", "zip/" + zip_file)
    return {"status": "ok"}
