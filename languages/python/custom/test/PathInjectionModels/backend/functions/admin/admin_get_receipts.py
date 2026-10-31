import os
import zipfile

import boto3


def download_dir(client, resource, dist, local="/tmp", bucket="receipts"):
    paginator = client.get_paginator("list_objects")
    for result in paginator.paginate(Bucket=bucket, Delimiter="/", Prefix=dist):
        if result.get("Contents") is not None:
            for file in result.get("Contents"):
                resource.meta.client.download_file(bucket, file.get("Key"), local + os.sep + file.get("Key"))  # $ Alert[py/path-injection]


def lambda_handler(event, context):  # $ Source[py/path-injection]
    client = boto3.client("s3")
    resource = boto3.resource("s3")
    y = event["year"]
    m = event["month"] + "/"
    prefix = "{}/{}".format(y, m)
    download_dir(client, resource, prefix, "/tmp", "receipts")
    zip_file = "{}receipts.zip".format(prefix.replace("/", "-"))
    zf = zipfile.ZipFile("/tmp/" + zip_file, "w")  # $ Alert[py/path-injection]
    zf.close()
    client.upload_file("/tmp/" + zip_file, "receipts", "zip/" + zip_file)  # $ Alert[py/path-injection]
    return {"status": "ok"}
