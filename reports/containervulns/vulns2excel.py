# -*- coding: utf-8 -*-
"""
Example script showing how to use the LaceworkClient class.
"""

import logging
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from laceworksdk import LaceworkClient
import pandas as pd
import json
import hashlib

logging.basicConfig(level=logging.INFO)

load_dotenv()

if __name__ == "__main__":
    howManyDaysAgo = 30
    filename = "vulns.xlsx"

    def getVulnsByDate(offset):
        # Instantiate a LaceworkClient instance
        lacework_client = LaceworkClient()

        # Build start/end times
        current_time = datetime.now(timezone.utc)
        start_time = current_time - timedelta(days=offset)
        end_time = current_time - timedelta(days=offset-1)
        start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S%z")
        end_time = end_time.strftime("%Y-%m-%dT%H:%M:%S%z")
        print("Searching between dates", start_time, end_time)

        # Get active containers for the timeframe
        active_containers_search = lacework_client.entities.containers.search(
            json={
                "timeFilter": {
                    "startTime": start_time,
                    "endTime": end_time,
                },
                "returns": [
                    "startTime",
                    "endTime",
                    "podName",
                    "mid",
                    "containerName",
                    "propsContainer",
                    "imageId",
                    "tags"
                ]
            }
        )

        image_ids = set() #unique list of image IDs used to look up vulns
        machine_ids = set() #unique list of machine IDs used by the containers for machine info lookup
        active_containers = list() #raw active containers, can be 23-24 rows per container hash
        unique_active_containers = dict() #need to find unique active containers, by default 1 per hour is returned, so 23-24 rows per container hash returned
        for page in active_containers_search:
            for item in page["data"]:
                active_containers.append(item)
                image_ids.add(item["imageId"])
                machine_ids.add(item["mid"])
                unique_active_containers[item["containerName"]] = item

        machines = lacework_client.entities.machines.search(
            json={
                "timeFilter": {
                    "startTime": start_time,
                    "endTime": end_time,
                },
                "filters": [
                {
                    "field": "mid",
                    "expression": "in",
                    "values": list(machine_ids)
                }],
                "returns": [
                    "mid",
                    "hostname",
                    "machineTags",
                    "primaryIpAddr"
                ]
            }
        )

        machine_info = dict()
        for page in machines:
            for item in page["data"]:
                instanceId = ""
                if item["machineTags"].get("AmiId"):
                    instanceId = item["machineTags"].get("AmiId")
                elif item["machineTags"].get("InstanceId"):
                    instanceId = item["machineTags"].get("InstanceId")

                
                machine_info[item["mid"]] = {
                    "ipAddress": item["primaryIpAddr"],
                    "hostname": item["hostname"],
                    "cluster": item["machineTags"].get("lw_KubernetesCluster"),
                    "instanceId": instanceId
                }

        active_container_vulns = lacework_client.vulnerabilities.containers.search(
            json={
                "timeFilter": {
                    "startTime": start_time,
                    "endTime": end_time,
                },
                "filters": [
                    {
                        "field": "imageId",
                        "expression": "in",
                        "values": list(image_ids)
                    },
                    {
                        "field": "severity",
                        "expression": "in",
                        "values": [
                            "Critical",
                            "High"
                        ]
                    },
                    {
                        "field": "status",
                        "expression": "eq",
                        "value": "VULNERABLE"
                    },
                    {
                        "field": "fixInfo.fix_available",
                        "expression": "eq",
                        "value": 1
                    }
                ],
                "returns": [
                    "evalCtx",
                    "evalGuid",
                    "featureKey",
                    "featureProps",
                    "fixInfo",
                    "imageId",
                    "severity",
                    "startTime",
                    "status",
                    "vulnId"
                ]
            }
        )
        
        vulns = dict()
        for page in active_container_vulns:
            for cve in page["data"]: 
                image_id = cve["imageId"]
                hoursRan = dict()
                
                #calculate hours ran for each container based off # of times it comes back in the response 
                for container in active_containers:
                    if container["imageId"] == image_id:
                        if hoursRan.get(container["podName"]) == None: #default count to 0
                            hoursRan[container["podName"]] = 0
                        hoursRan[container["podName"]] += 1

                for k in unique_active_containers:
                    container = unique_active_containers[k]
                    if container["imageId"] == image_id:
                        machine_id = container["mid"]
                        machine_details = machine_info[machine_id]

                        c = {
                            "vulnID": cve["vulnId"],
                            "severity": cve["severity"],
                            "status": cve["status"],
                            "packageName": cve["featureKey"]["name"],
                            "packageNamespace": cve["featureKey"]["namespace"],
                            "fixedVersion": cve["fixInfo"]["fixed_version"],
                            "imageId": image_id,
                            "hoursRan": hoursRan[container["podName"]],
                            "containerName": container["containerName"],
                            "ipAddress": machine_details["ipAddress"],
                            "hostname": machine_details["hostname"],
                            "instanceId": machine_details["instanceId"],
                            "clusterName": machine_details["cluster"],
                            "imageRepo": container["propsContainer"]["IMAGE_REPO"],
                            "imageVersion": container["propsContainer"]["IMAGE_VERSION"],
                            "imageTag": container["propsContainer"]["IMAGE_TAG"],
                            "namespace": container["propsContainer"]["PROPS_LABEL"]["io.kubernetes.pod.namespace"],
                            "podName": container["podName"]
                        }
                        containerhash = cve["vulnId"] + container["containerName"] + cve["featureKey"]["name"] + machine_details["instanceId"]

                        strhash = hashlib.sha256(containerhash.encode()).hexdigest()
                        vulns[strhash] = c
        
        return vulns

    def getVulnHashDiff(first, second):
        firstHashes = first.keys()
        secondHashes = second.keys()

        diff = [x for x in firstHashes if x not in secondHashes]
        return diff

    def getFullVulnData(vulns, hashes):
        data = dict()
        for h in hashes:
            data[h] = vulns[h]
        return data
        
    def getFormattedData(data):
        csv = list()
        for k in data:
            c = data[k]
            csv.append({
                "CVE": c["vulnID"],
                "Severity": c["severity"],
                "Status": c["status"],
                "Package Name": c["packageName"],
                "Package Namespace": c["packageNamespace"],
                "Fixed Version": c["fixedVersion"],
                "Image ID": c["imageId"],
                "Instance ID": c["instanceId"],
                "Hostname": c["hostname"],
                "IP Address": c["ipAddress"],
                "Cluster Name": c["clusterName"],
                "Namespace": c["namespace"],
                "Pod Name": c["podName"],
                "Image Repo": c["imageRepo"],
                "Image Version": c["imageVersion"],
                "Image Tag": c["imageTag"],
                "Hours Observed": c["hoursRan"]
            })
        return csv

    previousVulns = getVulnsByDate(30) #grab vulns from last month
    currentVulns = getVulnsByDate(1) #grab current vulns

    fixedVulnHashes = getVulnHashDiff(previousVulns, currentVulns) #figure out which vulns have been fixed since last month
    newVulnHashes = getVulnHashDiff(currentVulns, previousVulns) #figure out which vulns are new since last month

    fixedVulnsData = getFullVulnData(previousVulns, fixedVulnHashes)
    newVulnsData = getFullVulnData(currentVulns, newVulnHashes)

    writer = pd.ExcelWriter(filename , engine='xlsxwriter')

    df1 = pd.DataFrame(getFormattedData(previousVulns))
    df2 = pd.DataFrame(getFormattedData(currentVulns))
    df3 = pd.DataFrame(getFormattedData(fixedVulnsData))
    df4 = pd.DataFrame(getFormattedData(newVulnsData))
    df1.to_excel(writer, sheet_name='Last Month')
    df2.to_excel(writer, sheet_name='Current')
    df3.to_excel(writer, sheet_name='Fixed Since Last Month')
    df4.to_excel(writer, sheet_name='New Since Last Month')
    writer.close()
    
    exit()