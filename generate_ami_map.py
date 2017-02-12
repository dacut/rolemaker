#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
from bs4 import BeautifulSoup
from HTMLParser import HTMLParser
from urllib2 import urlopen
page = urlopen("https://aws.amazon.com/amazon-linux-ami/").read()
#page = open("/tmp/instances.html", "r").read()
page = page.replace("<br />", " ").replace("  ", " ")

region_name_to_code = {
    u"AWS GovCloud": "us-gov-west-1",
    u"Asia Pacific Mumbai": "ap-south-1",
    u"Asia Pacific Seoul": "ap-northeast-2",
    u"Asia Pacific Singapore": "ap-southeast-1",
    u"Asia Pacific Sydney": "ap-southeast-2",
    u"Asia Pacific Tokyo": "ap-northeast-1",
    u"Canada Central": "cn-central-1",
    u"China Beijing": "cn-north-1",
    u"EU Frankfurt": "eu-central-1",
    u"EU Ireland": "eu-west-1",
    u"EU London": "eu-west-2",
    u"South America São Paulo": "sa-east-1",
    u"US East N. Virginia": "us-east-1",
    u"US East Ohio": "us-east-2",
    u"US West N. California": "us-west-1",
    u"US West Oregon": "us-west-2",
}

ami_types = ("HVM64_EBS", "HVM64_Instance", "PV64_EBS", "PV64_Instance",)

soup = BeautifulSoup(page, "html.parser")
region_rows = soup.find("div", class_="aws-table").find_all("tr")[1:]
results = {}

for region_row in region_rows:
    cells = region_row("td")[:5]

    if not all([(
            len(cell.contents) == 1 and
            isinstance(cell.contents[0], basestring)) for cell in cells]):
        raise ValueError("Could not decode region row: %r" % region_row)

    region_name = cells[0].contents[0]
    try:
        region_code = region_name_to_code[region_name]
    except KeyError:
        print(region_name)
        print(region_name_to_code.keys())
        raise
    ami_ids = [cell.contents[0] for cell in cells[1:5]]

    results[region_code] = ami_ids

print("  AMI:")
for region_code, ami_ids in sorted(results.iteritems()):
    print("    %s:" % region_code)
    for ami_type, ami_id in zip(ami_types, ami_ids):
        if ami_id == "n/a":
            continue
        print("      %s: %s" % (ami_type, ami_id))


# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
