#!/usr/bin/python

from cryptography.fernet import Fernet
from termcolor import colored, cprint
import json
import jsonschema
import os
import sys

scriptDir = os.path.dirname(os.path.realpath(__file__))

def main():
    actionsDict = {
        1: addPassword,
        2: getPassword,
        3: printLabelDetails,
        4: printLabels,
        5: dumpDecryptedPasswords,
        6: changePassword,
    }

    data = checkFiles()
    function = determineSource(data)

    function(data, actionsDict)


# END main() DEF


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
        "0) Exit",
        "",
    ]

    choice = -1

    while choice != 0:
        try:
            for item in menu:
                print(item)
            # END FOR

            choice = int(raw_input("Choice: "))

            if choice > 0 and choice < 7:
                actionsDict[choice](data)
            elif choice == 0:
                sys.exit(0)
            else:
                print('\nInvalid choice "{}". Try Again\n.'.format(choice))
            # END IF
        except ValueError:
            print("\nNon numeric value detected, please enter a numeric choice.\n")
        # END TRY


# END terminal() DEF


def processCommandLineRequest(data, actionsDict):
    source_data = data["source_data"]

    validateData(source_data)

    data["key"] = bytes(data["source_data"].pop("key"))
    actionsDict[source_data["action"]](data)


# END processCommandLineRequest() DEF


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
        print(usageFile.read())
    #END WITH
    
    sys.exit(0)


#END usage() DEF


def information():
    global scriptDir

    with open(scriptDir + "/info.txt", "r") as infoFile:
        print(infoFile.read())
    # END WITH

    sys.exit(0)


# END information() DEF

def displaySchema(schema_id):
    global scriptDir

    schema_files = {
        1: "/schemas/addpassword.json",
        2: "/schemas/getpassword.json",
        3: "/schemas/getlabelinfo.json",
        4: "/schemas/getlabels.json",
        5: "/schemas/dump.json",
        6: "/schemas/changepassword.json"
    }

    with open(scriptDir + schema_files[schema_id], "r") as schema:
        print(schema.read())
    # END WITH

    sys.exit()


# END displaySchemas() DEF

###################################################################################################
#    _        _   _               _____                 _   _                 
#   / \   ___| |_(_) ___  _ __   |  ____   _ _ __   ___| |_(_) ___  _ __  ___ 
#  / _ \ / __| __| |/ _ \| '_ \  | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# / ___ | (__| |_| | (_) | | | | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#/_/   \_\___|\__|_|\___/|_| |_| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#                                                                              
###################################################################################################
def addPassword(data):
    fileName = data["fileName"]
    passwords = data["passwords"]
    key = data["key"]
    cipher_suite = Fernet(key)
    mirrorOtherLabel = ""
    lableToMirror = ""

    if data["source"] == "cmd_arg":
        info = data["source_data"]["passwordInfo"]
        pwUserName = info["pwUserName"]
        pwLabel = info["pwLabel"]
        pwVal = info["pwLabel"]
        pwURL = info["pwURL"]
        pwDesc = info["pwDesc"]
        pwDetails = info["pwDetails"]
    else:
        mirrorOtherLabel = raw_input("\nMirror username and password of other label? (yes/no): ")

        if mirrorOtherLabel == "yes":
            lableToMirror = raw_input("What label do you want to mirror?: ")

            if lableToMirror in passwords:
                pwUserName = passwords[lableToMirror]["username"]
                pwVal = passwords[lableToMirror]["value"]
            else:
                print("\nLabel \"{}\" not found.".format(lableToMirror))
        # END IF
    # END IF

        pwUserName = raw_input("Enter user name to be associated with this password: ")
        pwLabel = raw_input("Enter label for password: ").lower()
        pwVal = raw_input("Enter password to be stored: ")
        pwURL = raw_input(
            "Enter URL for password (if there is one, can leave blank for default value of N/A): "
        )
        pwDesc = raw_input("Enter a brief description of the password (optional): ")
        pwDetails = raw_input(
            "*Optional* Enter details(i.e. security questions). Separate values via commas: "
        )
    # END IF
    
    details = pwDetails.split(",")
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


    if pwURL == "":
        pwURL = "N/A"

    if pwLabel in passwords.keys():
        print(
            '\nLabel "{}" already has a password. Duplicate labels not allowed.'.format(
                pwLabel
            )
        )
    else:
        with open(fileName, "w") as passwordsData:
            passwords[pwLabel] = {}
            passwords[pwLabel]["username"] = pwUserName
            passwords[pwLabel]["value"] = cipher_suite.encrypt(pwVal)
            passwords[pwLabel]["url"] = pwURL
            passwords[pwLabel]["description"] = pwDesc
            passwords[pwLabel]["details"] = details

            passwordsData.write(json.dumps(passwords))
        # END WITH
    # END IF


# END addPassword() DEF


def getPassword(data):
    passwords = data["passwords"]

    if len(passwords.keys()) == 0:
        print("\nThere are no passwords stored to get.")
    else:
        if data["source"] == "terminal":
            pwLabel = raw_input("\nEnter label of password to look for: ").lower()
        else:
            pwLabel = data["source_data"]["label"]
        # END IF

        if pwLabel not in passwords.keys():
            print('\nLabel "{}" does not exist.'.format(pwLabel))
        else:
            try:
                key = data["key"]
                cipher_suite = Fernet(key)
                encryptedPw = passwords[pwLabel]["value"]
                print(
                    '\nPassword for label "{}": {}'.format(
                        pwLabel, cipher_suite.decrypt(bytes(encryptedPw))
                    )
                )
            except ValueError:
                print('\nWrong key for label "{}"'.format(pwLabel))
            # END TRY
        # END IF
    # END IF


# END getPassword() DEF


def changePassword(data):
    passwords = data["passwords"]

    if len(passwords.keys()) == 0:
        print("\nThere are no passwords stored to change.")
    else:
        pwLabel = raw_input("\nEnter the label for password to change: ")

        if pwLabel in passwords.keys():
            try:
                key = data["key"]
                cipher_suite = Fernet(key)
                newPw = raw_input("Etner new password: ")
                passwords[pwLabel]["value"] = cipher_suite.encrypt(newPw)
            except ValueError:
                print('\nWrong key for label "{}"'.format(pwLabel))
            # END TRY
        else:
            print('\nLabel "{}" does not exist.'.format(pwLabel))
        # END IF
    # END IF


# END changePassword() DEF


def printLabelDetails(data):
    passwords = data["passwords"]

    pwLabel = raw_input("\nEnter label to print information for: ").lower()

    if pwLabel in passwords.keys():
        print(json.dumps(passwords[pwLabel], indent=4))
    else:
        print('\nLabel "{}" not found.'.format(pwLabel))
    # END IF


# END printLableDetails() DEF


def printLabels(data):
    print("\nLabels curently stored:\n")
    count = 1

    for label in data["passwords"].keys():
        print("{}) {}".format(count, label))
        count = count + 1
    # END FOR


# END printLabels() DEF


def dumpDecryptedPasswords(data):
    if data["source"] == "terminal":
        fileDir = raw_input(
            "\nEnter directory where to dump file in (Dont use directory of this script): "
        )
    else:
        fileDir = data["source_data"]["fileDir"]
    # END IF

    if os.path.exists(fileDir):
        with open(fileDir + "/passwords.json", "w+") as fileObj:
            decryptedPasswords = data["passwords"].copy()
            key = data["key"]
            cipher_suite = Fernet(key)

            for item in decryptedPasswords.values():
                try:
                    encryptedPw = item["value"]
                    item["value"] = cipher_suite.decrypt(bytes(encryptedPw))
                except ValueError:
                    print("\nKey provided is not the correct key to decrypt passwords.")
                # END TRY

            fileObj.write(json.dumps(decryptedPasswords, indent=4))
        # END WITH
    else:
        print("\n{} is not a valid directory".format(fileDir))
    # END IF


# END dumpDecryptedPasswords() DEF


def generateKey():
    print("\nHere is a new key.")


# END generateKey() DEF


###################################################################################################
# __     __    _ _     _       _   _               _____                 _   _                 
# \ \   / __ _| (_) __| | __ _| |_(_) ___  _ __   |  ____   _ _ __   ___| |_(_) ___  _ __  ___ 
#  \ \ / / _` | | |/ _` |/ _` | __| |/ _ \| '_ \  | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
#   \ V | (_| | | | (_| | (_| | |_| | (_) | | | | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#    \_/ \__,_|_|_|\__,_|\__,_|\__|_|\___/|_| |_| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#                                                                                              
###################################################################################################
def determineSource(data):
    if len(sys.argv) > 1:
        if sys.argv[1] == "-f":
            with open(sys.argv[2], "r") as json_file:
                data["source_data"] = json.loads(json_file.read())
            # END WITH
        elif sys.argv[1] == "-j":
            data["source_data"] = json.loads(sys.argv[2])
        elif sys.argv[1] == "-i":
            information()
        elif sys.argv[1] == "-u":
            print("")
            usage()
        elif sys.argv[1] == "-s":
            displaySchema(int(sys.argv[2]))
        else:
            print("\nInvalid option \"{}\"".format(sys.argv[1]))
            usage()
        # END IF

        data["source"] = "cmd_arg"
        function = processCommandLineRequest
    else:
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

    if not os.path.exists(scriptDir + "/created.txt"):
        with open(scriptDir + "/created.txt", "w+") as createFile:
            promptString = "\nIt does not appear that a key has been generated before,"
            promptString = promptString + " here is a key: {}"
            promptString = promptString + "\nBeware that this key will not be saved and you are"
            promptString = promptString + " responsible for it. If you lose it you will not"
            promptString = promptString + " be able to get your passwords"
            promptString = promptString + "\nfrom here. You can generate a new key but will need"
            promptString = promptString + " to reset passwords.\n"
            print(promptString.format(Fernet.generate_key()))
            createFile.write("created")
        # END WITH
    # END IF

    data = {"fileName": scriptDir + "/passwords.json", "passwords": passwords}

    return data


# END checkFiles() DEF


def validateData(source_data):
    if "action" not in source_data.keys():
        print("Key \"action\" missing from input json data. Invalid JSON data.")
        sys.exit(1)
    # END IF

    action = source_data["action"]
    
    if type(action) is not int:
        print(color("Key \"action\" for incoming JSON data is not integer. Invalid JSON data.",
                    "red")
        )
        sys.exit(1)
    # END IF

    global scriptDir

    schema_paths = {
        1: "/schemas/addpassword.json",
        2: "/schemas/getpassword.json",
        3: "/schemas/getlabelinfo.json",
        4: "/schemas/getlabels.json",
        5: "/schemas/dump.json",
        6: "/schemas/changepassword.json"
    }

    dataTypes = {
        type(""): "string",
        type(1): "integer",
        type(True): "boolean",
        type([]): "list",
        type({}): "object"
    }

    full_schema_path = scriptDir + schema_paths[action]

    with open(full_schema_path) as schema_file:
        try:
            schema_obj = json.loads(schema_file.read())
            jsonschema.validate(source_data, schema_obj)
        except jsonschema.exceptions.ValidationError as e:
            errInfo = e._contents()
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
                message = message + "\nIcoming JSON: \n"

                for prop in list(errPath)[1:]:
                    if prop in currObj.keys():
                        currObj = currObj[prop]
                    # END IF
                #END

                currObj[issueKey] = "Bad Key: This key is missing <---"
            elif errValidator == "type":
                for prop in list(errPath)[1:-1]:
                    if prop in currObj.keys():
                        currObj = currObj[prop]
                    # END IF
                #END

                issueKey = list(errPath)[-1]
                expectedType = errInfo["validator_value"].replace("u'", "").replace("'", "")
                message = "\nKey \"{}\" is wrong type in incoming JSON data".format(issueKey)
                message = message + "\nExpected type({}), got type({})".format(
                    expectedType, dataTypes[type(currObj[issueKey])]
                )
                message = message + "\nJSON Path of key: {}".format(".".join(errPath))
                message = message + "\nIcoming JSON: \n"

                issueLine = "Bad Key: {} (wrong type got [{}], expected [{}]) <---"
                issueLine = issueLine.format(
                    currObj[issueKey],  dataTypes[type(currObj[issueKey])], expectedType
                )

                currObj[issueKey] = issueLine
            else:
                print(e)
                sys.exit(1)
            # END IF

            message = message + json.dumps(source_data, indent = 4)

            for line in message.split("\n"):
                if not line.find("Bad Key: ") == -1:
                    print(colored(line.replace("Bad Key: ", ""), "red"))
                else:
                    print(line)
                # END IF
            # END FOR

            sys.exit(1)
        # END TRY
    # END WITH


# END validateKeys() DEF


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
