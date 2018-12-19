#!/usr/bin/python

from cryptography.fernet import Fernet
import json
import copy
import jsonschema
import os
import sys
from termcolor import colored

printSource = ""
scriptDir = os.path.dirname(os.path.realpath(__file__))


def main():
    actionsDict = {
        1: addPassword,
        2: getPassword,
        3: printLabelDetails,
        4: printLabels,
        5: dumpDecryptedPasswords,
        6: changePassword,
        7: generateKey,
        0: exit
    }

    data = checkFiles()
    function = determineSource(data)

    function(data, actionsDict)


# END main() DEF


# --------------------
# Control Functions  |
###################################################################################################
#   ____            _             _   _____                 _   _
#  / ___|___  _ __ | |_ _ __ ___ | | |  ____   _ _ __   ___| |_(_) ___  _ __  ___
# | |   / _ \| '_ \| __| '__/ _ \| | | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |__| (_) | | | | |_| | | (_) | | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#  \____\___/|_| |_|\__|_|  \___/|_| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################
def terminal(data, actionsDict):
    data["key"] = raw_input("Please enter key for passwords: ")

    menu = [
        "",
        "1) Add Password",
        "2) Get Password",
        "3) Get Full Details For A Label (Password Encrypted)",
        "4) List All Labels",
        "5) Dump Decrypted Info To New File.",
        "6) Change Password",
        "7) Generate New Key",
        "0) Exit",
        "",
    ]

    while True:
        try:
            for item in menu:
                printMsg(item)
            # END FOR

            choice = int(raw_input("Choice: "))

            if isValidAction(choice):
                 actionsDict[choice](data)
            else:
                printMsg('\nInvalid choice "{}". Try Again\n.'.format(choice), "red")
            # END IF
        except ValueError:
            printMsg("\nNon numeric value detected, please enter a numeric choice.\n", "red")
        # END TRY


# END terminal() DEF


def processJSONRequest(data, actionsDict):
    source_data = data["source_data"]

    validateData(source_data)

    action = source_data["action"]

    if isValidAction(action):
        if "key" in data.keys():
            data["key"] = bytes(data["source_data"].pop("key"))
        # END IF

        actionsDict[action](data)
        # END IF
    else:
        printMsg('\nInvalid choice "{}". Try Again\n.'.format(action), "red")
    # END IF


# END processJSONRequest() DEF


def exit(data):
    sys.exit(0)


# END exit() DEF


# -----------------
# Info Functions  |
###################################################################################################
#  ___        __         _____                 _   _
# |_ _|_ __  / _| ___   |  ____   _ _ __   ___| |_(_) ___  _ __  ___
#  | || '_ \| |_ / _ \  | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
#  | || | | |  _| (_) | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |___|_| |_|_|  \___/  |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################
def usage():
    global scriptDir

    with open(scriptDir + "/usage.txt", "r") as usageFile:
        printMsg(usageFile.read())
    # END WITH

    sys.exit(0)


# END usage() DEF


def information():
    global scriptDir

    with open(scriptDir + "/info.txt", "r") as infoFile:
        printMsg(infoFile.read())
    # END WITH

    sys.exit(0)


# END information() DEF

# @displaySchema
def displaySchema(schema_id):
    global scriptDir

    schema_files = {
        1: "/schemas/addpassword.json",
        2: "/schemas/getpassword.json",
        3: "/schemas/getlabelinfo.json",
        4: "/schemas/getlabels.json",
        5: "/schemas/dump.json",
        6: "/schemas/changepassword.json",
        7: "/schemas/genkey.json"
    }

    with open(scriptDir + schema_files[schema_id], "r") as schema:
        printMsg(schema.read())
    # END WITH

    sys.exit(0)


# END displaySchema() DEF


# -------------------
# Action Functions  |
###################################################################################################
#     _        _   _               _____                 _   _
#    / \   ___| |_(_) ___  _ __   |  ____   _ _ __   ___| |_(_) ___  _ __  ___
#   / _ \ / __| __| |/ _ \| '_ \  | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
#  / ___ | (__| |_| | (_) | | | | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# /_/   \_\___|\__|_|\___/|_| |_| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################

# @addPssword()
def addPassword(data):
    fileName = data["fileName"]
    passwords = data["passwords"]
    key = data["key"]
    cipher_suite = Fernet(key)

    pwUserName, pwVal, pwLabel, pwURL, pwDesc, pwDetails = gatherPasswordInfo(data, cipher_suite)
    # END IF

    encryptDetails(pwDetails, cipher_suite)

    if pwURL == "":
        pwURL = "N/A"

    if pwLabel in passwords.keys():
        printMsg(
            '\nLabel "{}" already has a password. Duplicate labels not allowed.'.format(
                pwLabel
            ), "red"
        )
    else:
        with open(fileName, "w") as passwordsData:
            passwords[pwLabel] = {}
            passwords[pwLabel]["username"] = pwUserName
            passwords[pwLabel]["value"] = cipher_suite.encrypt(bytes(pwVal))
            passwords[pwLabel]["url"] = pwURL
            passwords[pwLabel]["description"] = pwDesc
            passwords[pwLabel]["details"] = pwDetails

            passwordsData.write(json.dumps(passwords))
        # END WITH
    # END IF


# END addPassword() DEF


# @getPassword()
def getPassword(data):
    passwords = data["passwords"]

    if len(passwords.keys()) == 0:
        printMsg("\nThere are no passwords stored to get.", "red")
    else:
        if data["source"] == "terminal":
            pwLabel = raw_input("\nEnter label of password to look for: ").lower()
        else:
            pwLabel = data["source_data"]["label"]
        # END IF

        if pwLabel not in passwords.keys():
            printMsg('\nLabel "{}" does not exist.'.format(pwLabel), "red")
        else:
            try:
                key = data["key"]
                cipher_suite = Fernet(key)
                encryptedPw = passwords[pwLabel]["value"]
                printMsg(
                    '\nPassword for label "{}": {}'.format(
                        pwLabel, cipher_suite.decrypt(bytes(encryptedPw))
                    )
                )
            except ValueError:
                printMsg('\nWrong key for label "{}"'.format(pwLabel))
            # END TRY
        # END IF
    # END IF


# END getPassword() DEF


def changePassword(data):
    passwords = data["passwords"]

    if len(passwords.keys()) == 0:
        printMsg("\nThere are no passwords stored to change.", "red")
    else:
        pwLabel = raw_input("\nEnter the label for password to change: ")

        if pwLabel in passwords.keys():
            try:
                key = data["key"]
                cipher_suite = Fernet(key)
                newPw = raw_input("Etner new password: ")
                passwords[pwLabel]["value"] = cipher_suite.encrypt(newPw)
            except ValueError:
                printMsg('\nWrong key for label "{}"'.format(pwLabel))
            # END TRY
        else:
            printMsg('\nLabel "{}" does not exist.'.format(pwLabel))
        # END IF
    # END IF


# END changePassword() DEF


def printLabelDetails(data):
    passwords = data["passwords"]

    if data["source"] == "terminal":
        pwLabel = raw_input("\nEnter label to print information for: ").lower()
    else:
        pwLabel = data["source_data"]["label"]
    # END IF

    if pwLabel in passwords.keys():
        printMsg(json.dumps(passwords[pwLabel], indent=4))
    else:
        printMsg('\nLabel "{}" not found.'.format(pwLabel))
    # END IF


# END printLableDetails() DEF


# @printLabels()
def printLabels(data):
    lablesString = "\nLabels curently stored:"
    count = 1

    for label in data["passwords"].keys():
        lablesString = lablesString + "\n {}) {}".format(count, label)
        count = count + 1
    # END FOR

    printMsg(lablesString)

# END printLabels() DEF


# @dumpDecryptedPasswords
def dumpDecryptedPasswords(data):
    if data["source"] == "terminal":
        fileDir = raw_input(
            "\nEnter directory where to dump file in (value \"stdout\" outputs to screen): "
        )
    else:
        fileDir = data["source_data"]["fileDir"]
    # END IF

    decryptedPasswords = copy.deepcopy(data["passwords"])
    key = data["key"]
    cipher_suite = Fernet(key)

    for item in decryptedPasswords.values():
        try:
            encryptedPw = item["value"]
            item["value"] = cipher_suite.decrypt(bytes(encryptedPw))
            item["details"] = decryptDetails(item["details"], cipher_suite)
        except ValueError:
            printMsg("\nKey provided is not the correct key to decrypt passwords.")
        # END TRY
    # END FOR

    if fileDir == "stdout":
        printMsg(json.dumps(decryptedPasswords, indent=4))
    elif os.path.exists(fileDir):
        with open(fileDir + "/pwdump.json", "w+") as fileObj:
            fileObj.write(json.dumps(decryptedPasswords, indent=4))
        # END WITH
    else:
        printMsg("\n{} is not a valid directory or is not \"stdout\"".format(fileDir))
    # END IF


# END dumpDecryptedPasswords() DEF


# @generateKey()
def generateKey(data):
    global scriptDir

    promptString = "\n"

    if os.path.exists(scriptDir + "/keygen.txt"):
        with open(scriptDir + "/keygen.txt", "r") as keyGenFile:
            promptString = promptString + keyGenFile.read()
        # END WITH
    # END IF

    printMsg(promptString.format(Fernet.generate_key()))


# END generateKey() DEF


# -----------------------
# Validation Functions  |
###################################################################################################
# __     __    _ _     _       _   _               _____                 _   _
# \ \   / __ _| (_) __| | __ _| |_(_) ___  _ __   |  ____   _ _ __   ___| |_(_) ___  _ __  ___
#  \ \ / / _` | | |/ _` |/ _` | __| |/ _ \| '_ \  | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
#   \ V | (_| | | | (_| | (_| | |_| | (_) | | | | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#    \_/ \__,_|_|_|\__,_|\__,_|\__|_|\___/|_| |_| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################

# @determineSource()
def determineSource(data):
    global printSource

    if len(sys.argv) > 1:
        printSource = "json"

        if sys.argv[1] == "-f":
            data["source_data"] = validateJsonFile(sys.argv[2])
        elif sys.argv[1] == "-j":
            try:
                data["source_data"] = json.loads(sys.argv[2])
            except ValueError as e:
                printMsg("Could not decode JSON Object", "red")
            # END TRY
        elif sys.argv[1] == "-i":
            information()
        elif sys.argv[1] == "-u":
            printMsg("")
            usage()
        elif sys.argv[1] == "-s":
            if isValidSchemaId(sys.argv[2]):
                displaySchema(sys.argv[2])
            else:
                sys.exit(1)
            # END IF
        else:
            printMsg("\nInvalid option \"{}\"".format(sys.argv[1]), "red")
            usage()
        # END IF

        # If execution made it here then the source has to be from JSON data.
        data["source"] = "json"
        function = processJSONRequest
    else:
        printSource = "terminal"
        data["source"] = "terminal"
        function = terminal
    # END IF

    return function


# END determineSource() DEF


def checkFiles():
    global scriptDir

    if not os.path.exists(scriptDir + "/passwords.json"):
        with open(scriptDir + "/passwords.json", "w+") as passwordsData:
            passwordsData.write("")
        # END WITH
    # END IF

    with open(scriptDir + "/passwords.json", "r+") as passwordsData:
        try:
            passwords = json.loads(passwordsData.read())
        except ValueError:
            passwords = {}
        # END TRY
    # END WITH

    data = {"fileName": scriptDir + "/passwords.json", "passwords": passwords}

    return data


# END checkFiles() DEF


def validateData(source_data):
    """
    The "action" key has to be checked before any actual JSON schema validation because its value
    will be used to determine which schema file to load to compare the incoming JSON dta to.
    """
    if "action" not in source_data.keys():
        printMsg("Key \"action\" missing from input json data. Invalid JSON data.")
        sys.exit(1)
    # END IF

    action = source_data["action"]

    if type(action) is not int:
        printMsg("Key \"action\" for incoming JSON data is not integer. Invalid JSON data.", "red")
        sys.exit(1)
    # END IF

    if not isValidAction(action):
        printMsg("Invalid value for key \"action\".", "red")
        sys.exit(1)
    # END IF

    global scriptDir

    schema_paths = {
        1: "/schemas/addpassword.json",
        2: "/schemas/getpassword.json",
        3: "/schemas/getlabelinfo.json",
        4: "/schemas/getlabels.json",
        5: "/schemas/dump.json",
        6: "/schemas/changepassword.json",
        7: "/schemas/genkey.json"
    }


    full_schema_path = scriptDir + schema_paths[action]

    with open(full_schema_path) as schema_file:
        try:
            schema_obj = json.loads(schema_file.read())
            jsonschema.validate(source_data, schema_obj)
        except jsonschema.exceptions.ValidationError as e:
            processSchemaError(e, source_data)
        # END TRY
    # END WITH


# END validateKeys() DEF

# @isValidAction()
def isValidAction(action):
    if action not in range(0, 8):
        return False

    return True


# END isValidAction


# -------------------
# Helper Functions  |
###################################################################################################
#  _   _      _                   _____                 _   _
# | | | | ___| |_ __   ___ _ __  |  ____   _ _ __   ___| |_(_) ___  _ __  ___
# | |_| |/ _ | | '_ \ / _ | '__| | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# |  _  |  __| | |_) |  __| |    |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_| |_|\___|_| .__/ \___|_|    |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#              |_|
###################################################################################################

# @validateJsonFile()
# Helper of function determineSource()
def validateJsonFile(fileName):
    returnData = {}

    try:
        with open(sys.argv[2], "r") as json_file:
            returnData = json.loads(json_file.read())
        # END WITH
    except IOError as e:
        printMsg("File {} not found.".format(sys.argv[2]), "red")
        sys.exit(1)
    except ValueError as e:
        printMsg("Could not decode JSON Object", "red")
        sys.exit(1)
    # END TRY

    return returnData


# END validateJsonFile() DEF


# @isValidSchemaId()
# Helper of function determineSource()
def isValidSchemaId(schema_id):
    action = schema_id

    try:
        action = int(action)

        if isValidAction(action):
            return True
        # END IF
    except ValueError as e:
        pass
    # END TRY

    # If execution reaches this point then something has gone wrong so print messsage.
    printMsg("Invalid value {} for schemaID. Use -i flag for options".format(action), "red")

    return False


#END isValidSchemaId() DEF

# @encryptDetails()
# Helper of function addPassword()
def encryptDetails(details, cipher_suite):
    printMsg(details)
    detIndex = 0
    splitWord = ""
    currentWord = ""

    for detail in details:
        for word in detail.split(" "):
            if not word.find("enc:|:") == -1:
                splitWord = word.split("enc:|:")
                currentWord = currentWord + " encrypted:" + splitWord[0]
                currentWord = currentWord + cipher_suite.encrypt(splitWord[1])
            else:
                currentWord = currentWord + " " + word
            # END IF
        # END FOR

        details[detIndex] = currentWord.lstrip()
        detIndex = detIndex + 1
        currentWord = ""
    # END FOR


# END encryptDetails() DEF


# @decryptDetails()
# Helper of function dumpDecryptedPasswords()
def decryptDetails(details, cipher_suite):
    decryptedDetails = []

    for detail in details:
        if not detail.find("encrypted:") == -1:
            splitDetail = detail.split("encrypted:")
            decryptedDetail = cipher_suite.decrypt(bytes(splitDetail[1]))
            decryptedDetail = "enc:|:" + decryptedDetail
            decryptedDetails.append(
                splitDetail[0].rstrip() + " " + decryptedDetail
            )
        else:
            decryptedDetails.append(detail)
        # END IF
    # END FOR

    return decryptedDetails


# END decryptDetails() DEF


# @gatherPasswordInfo()
# Helper of function addPassword()
def gatherPasswordInfo(data, cipher_suite):
    passwords = data["passwords"]

    if data["source"] == "json":
        info = data["source_data"]["passwordInfo"]

        if "mirrorLabel" in info.keys():
            if info["mirrorLabel"] in passwords.keys():
                pwUserName = passwords[lableToMirror]["username"]
                pwVal = cipher_suite.decrypt(bytes(passwords[lableToMirror]["value"]))
            else:
                printMsg("\nLabel \"{}\" not found.".format(lableToMirror))
                return
            # END IF
        else:
            pwUserName = info["pwUserName"]
            pwVal = info["pwVal"]
        # END IF

        pwLabel = info["pwLabel"]
        pwURL = info["pwURL"]
        pwDesc = info["pwDesc"]
        pwDetails = info["pwDetails"]
    else:
        mirrorOtherLabel = raw_input("\nMirror username and password of other label? (yes/no): ")

        if mirrorOtherLabel == "yes":
            lableToMirror = raw_input("What label do you want to mirror?: ")

            if lableToMirror in passwords:
                pwUserName = passwords[lableToMirror]["username"]
                pwVal = cipher_suite.decrypt(bytes(passwords[lableToMirror]["value"]))
            else:
                printMsg("\nLabel \"{}\" not found.".format(lableToMirror))
                return
        elif mirrorOtherLabel == "no":
            pwUserName = raw_input("Enter user name to be associated with this password: ")
            pwVal = raw_input("Enter password to be stored: ")
        else:
            printMsg("\nInvalid response \"{}\".".format(mirrorOtherLabel))
            return
        # END IF

        pwLabel = raw_input("Enter label for password: ").lower()
        pwURL = raw_input(
            "Enter URL for password (if there is one, can leave blank for default value of N/A): "
        )
        pwDesc = raw_input("Enter a brief description of the password (optional): ")
        pwDetails = raw_input(
            "*Optional* Enter details(i.e. security questions). Separate values via commas: "
        )
    # END IF

    pwDetails = pwDetails.split(",")

    return (pwUserName, pwVal, pwLabel, pwURL, pwDesc, pwDetails)
# END gatherPasswordInfo() DEF


# Helper of function validateData()
def processSchemaError(error, source_data):
    dataTypes = {
        type(""): "string",
        type(1): "integer",
        type(True): "boolean",
        type(1.23): "number",
        type([]): "list",
        type({}): "object"
    }

    errInfo = error._contents()
    errValidator = errInfo["validator"]
    errPath = errInfo["path"]
    errPath.appendleft("root")
    errMsg = errInfo["message"]
    issueKey = ""
    message = ""
    currObj = source_data
    expectedType =""

    if errValidator == "required":
        issueKey = errMsg.split(" ")[0].replace("u'", "").replace("'", "")
        errPath.append(issueKey)
        message = "\nRequired key \"{}\" missing from incoming JSON data".format(issueKey)
        message = message + "\nJSON Path of key: {}".format(".".join(errPath))
        message = message + "\nIncoming JSON: \n"

        for prop in list(errPath)[1:]:
            if prop in currObj.keys():
                currObj = currObj[prop]
            # END IF
        # END

        currObj[issueKey] = "This key is missing <---"
    elif errValidator == "type":
        for prop in list(errPath)[1:-1]:
            if prop in currObj.keys():
                currObj = currObj[prop]
            # END IF
        # END

        issueKey = list(errPath)[-1]
        expectedType = errInfo["validator_value"].replace("u'", "").replace("'", "")
        message = "\nKey \"{}\" is wrong type in incoming JSON data".format(issueKey)
        message = message + "\nExpected type({}), got type({})".format(
            expectedType, dataTypes[type(currObj[issueKey])]
        )
        message = message + "\nJSON Path of key: {}".format(".".join(errPath))
        message = message + "\nIncoming JSON: \n"

        issueLine = "{} (wrong type got [{}], expected [{}]) <---"
        issueLine = issueLine.format(
            currObj[issueKey],  dataTypes[type(currObj[issueKey])], expectedType
        )

        currObj[issueKey] = issueLine
    else:
        printMsg(error)
        sys.exit(1)
    # END IF

    message = message + json.dumps(source_data, indent = 4)

    printMsg(message, "red")

    sys.exit(1)


# END processSchemaError() DEF



# --------------------
# Utility Functions  |
###################################################################################################
#  _   _ _   _ _ _ _           _____                 _   _
# | | | | |_(_| (_| |_ _   _  |  ____   _ _ __   ___| |_(_) ___  _ __  ___
# | | | | __| | | | __| | | | | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |_| | |_| | | | |_| |_| | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#  \___/ \__|_|_|_|\__|\__, | |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#                      |___/
###################################################################################################

# @printMessage()
def printMsg(msgStr, colorStr="None"):
    global printSource

    printObj = None
    if  printSource == "json":
        response = {"response": {}}
        response["response"]["color"] = colorStr
        response["response"]["message"] = msgStr

        printObj = json.dumps(response)
    elif colorStr == "None":
        printObj = msgStr
    else:
        printObj = colored(msgStr, colorStr)
    # END IF

    print(printObj)


# END printMsg() DEF


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
        # END TRY
    # END TRY
else:
    raise ImportWarning("Do not import this module, run it as main.")
# END IF