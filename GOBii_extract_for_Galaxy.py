#!/usr/bin/env python
# title           :GOBii_extract_for_Galaxy.py
# description     :This will help the user to pull the data from GOBii using BrAPI calls.
# author          :s.sivasubramani@cgiar.org
# date            :20190729
# version         :0.1
# usage           :python GOBii_extract_for_Galaxy.py
# notes           :
# python_version  :3.7.4
# ==============================================================================

import requests
import sys
from optparse import OptionParser

PAGESIZE = 100000
usage = "usage: python %prog [options] \n\n\t\
%prog -m Authenticate -U http://hackathon.gobii.org:8081/gobii-dev/ -u username -p password \n\t\
%prog -m Variantset -U http://hackathon.gobii.org:8081/gobii-dev/ -x KYxmnDfwwgcIM+17tvavIlU -o outputFile\n\t\
%prog -m Extract -U http://hackathon.gobii.org:8081/gobii-dev/ -x KYxmnDfwwgcIM+17tvavIlU -v 4 -o outputFile\n\t\
"
parser = OptionParser(usage=usage)
parser.add_option("-m", "--module", dest="module",
                  help="One of the modules to perform. \"Authenticate\", \"Variantset\", \"Extract\"",
                  metavar="Authenticate")
parser.add_option("-U", "--url", dest="url", help="GDM url. eg: http://hackathon.gobii.org:8081/gobii-dev/",
                  metavar="URL")
parser.add_option("-u", "--username", dest="username", help="GDM username. eg: gadm", metavar="USERNAME")
parser.add_option("-p", "--password", dest="password", help="GDM password. eg: g0b11Admin", metavar="PASSWORD")
parser.add_option("-x", "--authToken", dest="authToken",
                  help="GDM Authentication Token for the API communitation. eg: "
                       "KYxmnDfwwgcIM+17tvavIlUScsxB3dVjUp/itwqWR5A=",
                  metavar="token")
parser.add_option("-v", "--variantsetID", dest="variantSetId", help="variantsetID to pul data from GDM.", metavar="4")
parser.add_option("-o", "--outFile", dest="outFile", help="Output file name.", metavar="FILE")
parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True,
                  help="don't print status messages to stdout")

(options, args) = parser.parse_args()
"""
function to extract the Access Token from GOBii GDM using Auth call
IMPORTANT: Make sure the api_path call it uses from gobii auth as BrAPI does not have auth calls
	url: GDM instance url (eg: http://hackathon.gobii.org:8081/gobii-dev/)
	username: GDM unstance username
	password: Password for the use 'username'
	return: access token pulled using the API
"""


def get_token(url, username, password):
    api_path = 'gobii/v1/auth'
    headers = {'X-Username': username, 'X-Password': password}
    r = requests.post(url + api_path, headers=headers)
    return (r.json()['token'])


"""
funtion to extract dictionary of information available under the GDM instance
IMPORTANT: Make sure the api_path call it uses from BrAPI
"""


def get_variantset_table(url, accessToken, outFile):
    '''
    funtion to extract dictionary of information available under the GDM instance
    :param url: GDM url eg: http://hackathon.gobii.org:8081/gobii-dev/
    :param accessToken: accessToken String got from getAccessToken
    :param outFile: OuputFile to create table of results
    :return: 
    '''
    api_path = 'brapi/v1/variantsets'
    headers = {'X-Auth-Token': accessToken}
    r = requests.get(url + api_path, headers=headers)
    return jsonToFile(r.json(), outFile)


def writeMatrixToFile(genotypeMatrix, outFile):
    '''

    :param genotypeMatrix:
    :param outFile:
    :return:
    '''
    outHeader = "marker_name"
    outFileHandle = open(outFile, 'w')
    for sampleName in genotypeMatrix['name']:
        outHeader = outHeader + "\t" + sampleName
    outFileHandle.write(outHeader + "\n")

    for markerName in genotypeMatrix:
        if markerName is not 'name':
            outString = markerName
            for sampleName in genotypeMatrix[markerName]:
                outString = outString + "\t" + genotypeMatrix[markerName][sampleName]
            outFileHandle.write(outString + "\n")
    return outFileHandle.close()


def get_variantset_matrix(url, accessToken, variantSetId, outFile):
    '''
    function to pull genotype matix and parse that to a tab
    :param url:
    :param accessToken:
    :param variantSetId:
    :param outFile:
    :return:
    '''
    api_path = 'brapi/v1/variantsets/' + variantSetId + "/calls"
    headers = {'X-Auth-Token': accessToken}
    params = {'pageSize': PAGESIZE}
    genotypeMatrix = {}
    pageToken = ""
    r = requests.get(url + api_path, params=params, headers=headers)
    if 'nextPageToken' in r.json()['metaData']['pagination']:
        pageToken = r.json()['metaData']['pagination']['nextPageToken']
    genotypeMatrix = jsonToDictionary(r.json(), genotypeMatrix)
    while pageToken:
        params = {'pageSize': PAGESIZE, 'pageToken': pageToken}
        r = requests.get(url + api_path, params=params, headers=headers)
        if 'nextPageToken' in r.json()['metaData']['pagination']:
            pageToken = r.json()['metaData']['pagination']['nextPageToken']
        else:
            pageToken = ""
        genotypeMatrix = jsonToDictionary(r.json(), genotypeMatrix)
    return writeMatrixToFile(genotypeMatrix, outFile)


"""
Example output for /brapi/v1/variantsets:
	"variantSetDbId": 3,
    "studyDbId": 2,
    "variantSetName": "sim_codominant_ds_01",
    "studyName": "sim_codominant_exp_01",
    "analyses": [
        {
            "createdDate": "2019-07-25T12:00:00",
            "analysisDbId": 1,
            "analysisName": "Test_Calling",
            "type": "calling",
            "description": "Test_Calling",
            "software": "Test_Calling_program"
        }
    ]
"""


def jsonToFile(jsonOut, outFile):
    '''
    For the Variantset module, API return the json object and this method prints the JSON as a table to the output file
    :param jsonOut: variantset BrAPI get request json object
    :param outFile: output file name to write the table to
    :return: closed the output file handle
    '''
    outFileHandle = open(outFile, 'w')
    header = "variantSetId" + "\t" + "variantSetName" + "\t" + "studyDbId" + "\t" + "studyName" + "\n"
    outFileHandle.write(header)
    for variantSet in jsonOut["result"]["data"]:
        variantSetId = variantSet["variantSetDbId"]
        studyDbId = variantSet["studyDbId"]
        variantSetName = variantSet["variantSetName"]
        studyName = variantSet["studyName"]
        outString = str(variantSetId) + "\t" + variantSetName + "\t" + str(studyDbId) + "\t" + studyName + "\n"
        outFileHandle.write(outString)
    return outFileHandle.close()


def jsonToDictionary(jsonOut, genotypeMatrix):
    '''
    converts variantset/calls BrAPI output json to a dictionary of marker and samples
    :param jsonOut:
    :param genotypeMatrix:
    :return:
    '''
    if 'name' not in genotypeMatrix:
        genotypeMatrix['name'] = {}
    for variantSet in jsonOut["result"]["data"]:
        callSetName = variantSet["callSetName"]
        variantName = variantSet["variantName"]
        genotype = variantSet["genotype"]['string_value']
        if callSetName not in genotypeMatrix['name']:
            genotypeMatrix['name'][callSetName] = callSetName
        if variantName not in genotypeMatrix:
            genotypeMatrix[variantName] = {}
        genotypeMatrix[variantName][callSetName] = genotype
    return genotypeMatrix


if options.module == "Authenticate":
    required = "url username password".split()
    for req in required:
        if options.__dict__[req] is None:
            parser.error("parameter %s required" % req)
    url = options.url
    username = options.username
    password = options.password
    outFile = options.outFile
    accessToken = get_token(url, username, password)
    print(accessToken)

elif options.module == "Variantset":
    required = "url authToken outFile".split()
    for req in required:
        if options.__dict__[req] is None:
            parser.error("parameter %s required" % req)
    url = options.url
    authToken = options.authToken
    outFile = options.outFile
    get_variantset_table(url, authToken, outFile)

elif options.module == "Extract":
    required = "url authToken variantSetId outFile".split()
    for req in required:
        if options.__dict__[req] is None:
            parser.error("parameter %s required" % req)
    url = options.url
    authToken = options.authToken
    variantSetId = options.variantSetId
    outFile = options.outFile
    get_variantset_matrix(url, authToken, variantSetId, outFile)

else:
    sys.stderr.write("Please specify the module.\n\n")
    parser.print_help()
    sys.exit(1)
