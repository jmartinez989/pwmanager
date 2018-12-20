#!/usr/bin/python

from cryptography.fernet import Fernet
import json
import copy
import jsonschema
import os
import sys
from termcolor import colored
from getpass import getpass

printSource = ""
scriptDir = os.path.dirname(os.path.realpath(__file__))

###################################################################################################
# @main()
# function main()
#
# Paramaters: None
#
# Returns: None
#
#     The main driver function.
def main():
    """
    Dictionary of functions to call. All of these functions are in the "Action Functions" section.
    """
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
###################################################################################################


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
#     The functions in this section are functions that control the flow of the program. The control
# functions will have a paramater called "data" that will be a dictionary that will hold many
# properties regarding the passwords stored. The dictionary will look like below:
#
# {
#     "data": {
#         "fileName": "",
#         "passwords": {
#             "passwordLabel1": {
#                 "description": "",
#                 "details":[],
#                 "url": "",
#                 "username": "",
#                 "value": ""
#             },
#             "passwordLabelN": {
#                 "description": "",
#                 "details":[],
#                 "url": "",
#                 "username": "",
#                 "value": ""
#             }
#         },
#         "key": "",
#         "source": "",
#         "source_data": {}
#     }
# }
#
# Below are descriptions of all of the properties of the data dictionary:
#     fileName: The fully qualified file name of the passwords file will be stored.
#     passwords: The dictionary storing all of the information that was stored in the password
#                file.
#     source: The source of where the input to the program will be coming from. This can either
#             be "terminal" or "json".
#     source_data: The actual data that is coming in from the source specified. This will only
#                  be populated when the "source" property is set to "json". The format for
#                  this will depend on what action is being requested by the JSON object passed
#                  in as input. The schema files will show what this should look like.
#     key: The key that will be used to encrypt/decrypt passwords. Certain action functions won't
#          actually need this key as these actions will not be handling actual passwords in any
#          way.
#
#
# Below are descriptions of all of the properties of the passwords dictionary:
#     passwordLabel1...passwordLabelN: The object that stores the password information. The key
#                                      is the label or name of the password object.
#
# Below are descriptions of the properties for a password object:
#     description: A brief description of where the password will be used. (optional)
#     details: A list of different details related to the password. This can be things like answers
#              to security or details on ip addresses to a device the password is associated with.
#              A list item can have a part or all of it encrypted by proceeding the word with the
#              prefix "enc:|:". (optional)
#     url: The URL of the site this password would be used on if it is applicaple (optional)
#     username: The username associated with the password.
#     value: The value of the actual password that is stored.
###################################################################################################


###################################################################################################
# @terminal()
# function terminal()
#
# Parameters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
#     actionsDict: A dictionary that will hold function pointers to the proper function to be
#                  called.
#
# Returns: None
#
#     This funtion will be used to direct the flow of control for when the source of input is the
# terminal. A menu will printed out to the screen for the user to show what actions they can take.
def terminal(data, actionsDict):
    data["key"] = getpass("Please enter key for passwords: ")

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
###################################################################################################


###################################################################################################
# @processJSONRequest()
# function processJSONRequest()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
#     actionsDict: A dictionary that will hold function pointers to the proper function to be
#                  called.
#
# Returns: None
#
#     This funtion will be used to direct the flow of control for when the source of input is
# coming from json.
def processJSONRequest(data, actionsDict):
    source_data = data["source_data"]

    validateData(source_data)

    action = source_data["action"]

    if isValidAction(action, "json"):
        if "key" in source_data.keys():
            data["key"] = bytes(data["source_data"].pop("key"))
        # END IF

        actionsDict[action](data)
        # END IF
    else:
        printMsg('\nInvalid choice "{}". Try Again\n.'.format(action), "red")
    # END IF


# END processJSONRequest() DEF
###################################################################################################


###################################################################################################
# @exit()
# function exit()
#
# Parameters:
#     data: Not actually used in this function. This function exists so that it can be stored in a
#           dictionary and invoked from it.
#
# Returns: None
#
#     This function is created so that it can be invoked from a dictionary that it will be stored
# in. The reason it will be stored in a dictionary is because there will be other functions in the
# dictionary that will be invoked based on an integer value. The dictionary this will be used on
# is essentially going to be treated as a switch statement where the integer chosen for an action
# will be the case and function will be called for that ase.
def exit(data):
    sys.exit(0)


# END exit() DEF
###################################################################################################


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
#     This section will have only functions that are used to inform the user of different aspects
# of the program.
###################################################################################################


###################################################################################################
# @usage()
# function usage()
#
# Parameters: None
#
# Returns: None
#
#     A function to display the usage of the program.
def usage():
    global scriptDir

    with open(scriptDir + "/usage.txt", "r") as usageFile:
        printMsg(usageFile.read())
    # END WITH

    sys.exit(0)


# END usage() DEF
###################################################################################################


###################################################################################################
# @information
# function information()
# Parameters: None
#
# Returns: None
#
#     A function to display specifics on how the program works with JSON input.
def information():
    global scriptDir

    with open(scriptDir + "/info.txt", "r") as infoFile:
        printMsg(infoFile.read())
    # END WITH

    sys.exit(0)


# END information() DEF
###################################################################################################


###################################################################################################
# @displaySchema
# function displaySchema()
#
# Parameters:
#     schema_id: The id of the schema to display.
#
# Returns: None
#
#     Function to display all of the JSON schemas for each of the actions that can be taken when
# using JSON as input for the program. The schema will be displayed in the format that is validated
# by the http://json-schema.org/draft-07 standard.
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
###################################################################################################


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
#     This section of functions are functions that actually perform the actions that are looking to
# be done such as adding a password, removing a password, updating passwords, etc..
###################################################################################################


###################################################################################################
# @addPassword()
# function addPassword()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
# Returns: None
#
#     A function to collect information to add a new password into the passwords file.
def addPassword(data):
    fileName = data["fileName"]
    passwords = data["passwords"]
    key = data["key"]
    cipher_suite = Fernet(key)

    info = gatherPasswordInfo(data, cipher_suite)

    """
    If the value returned from gathering password data was None/Null then just return None.
    """
    if not info:
        return
    # END IF

    pwUserName, pwVal, pwLabel, pwURL, pwDesc, pwDetails = info
    pwDetails = pwDetails.split(",")

    """
    Encrypt each item in the pwDetails list. Each item in the list is just basically a sentance
    and each word in the sentance can be encrypted with the prefix "enc:|:".
    """
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
###################################################################################################


###################################################################################################
# @getPassword()
# function getPassword()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
# Returns: None
#
#     This password will fetch the password being looked for, unencrypt it and then display it to
# the user.
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
                printMsg('\nWrong key for label "{}"'.format(pwLabel), "red")
            # END TRY
        # END IF
    # END IF


# END getPassword() DEF
###################################################################################################


###################################################################################################
# @changePassword()
# function changePassword()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
# Returns: None
#
#     A function to change the password being specified by a label/name.
def changePassword(data):
    global scriptDir

    pwFile = scriptDir + "/passwords.json"
    passwords = data["passwords"]
    source = data["source"]
    newPw = ""

    if len(passwords.keys()) == 0:
        printMsg("\nThere are no passwords stored to change.", "red")
        return
    # END IF

    if source == "json":
        pwLabel = data["source_data"]["label"]
        newPw = data["source_data"]["value"]
    else:
        pwLabel = raw_input("\nEnter the label for password to change: ")
    # END IF

    if pwLabel in passwords.keys():
        """
        This is checked second after the check for the label being in the list of stored labels
        because if the label does not exist then there is no need to ask for a new password.
        """
        if newPw == "":
            newPw = raw_input("Etner new password: ")
        # END IF

        try:
            key = data["key"]
            cipher_suite = Fernet(key)
            passwords[pwLabel]["value"] = cipher_suite.encrypt(bytes(newPw))

            with open(pwFile, "w") as pwFileObj:
                pwFileObj.write(json.dumps(passwords))
            # END WITH

            printMsg("\nUpdated password successfully", "green")
        except ValueError:
            printMsg('\nWrong key for label "{}"'.format(pwLabel), "red")
        # END TRY
    else:
        printMsg('\nLabel "{}" does not exist.'.format(pwLabel), "red")
    # END IF


# END changePassword() DEF
###################################################################################################


###################################################################################################
# @printLabelDetails()
# function printLabelDetails()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
# Returns: None
#
#     This function will print out all of the details of the password object with the requested label.
# It will display them in JSON notation and the actual password will be unencrypted.
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
###################################################################################################


###################################################################################################
# @printLabels()
# function printLabels()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
# Returns: None
#
#     This function will just print a list of all labels/names that are currently stored.
def printLabels(data):
    lablesString = "\nLabels curently stored:"
    count = 1

    if len(data["passwords"].keys()) > 1:
        for label in data["passwords"].keys():
            lablesString = lablesString + "\n {}) {}".format(count, label)

            printMsg(lablesString)

            count = count + 1
        # END FOR
    else:
        printMsg("\nNo labels are stored to print.", "red")
    # END IF

# END printLabels() DEF
###################################################################################################


###################################################################################################
# @dumpDecryptedPasswords
# function dumpDecryptedPasswords()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
# Returns: None
#
#     This function will write the value of the password file to another location but all of the
# passwords will be in clear text. This function also has the capability of displaying this
# information to the screen.
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
###################################################################################################


###################################################################################################
# @generateKey()
# function generateKey()
#
# Parameters:
#     data: Not actually used in this function. This function exists so that it can be stored in a
#           dictionary and invoked from it.
#
# Returns: None
#
#     Function to generate an encryption key.
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
###################################################################################################


###################################################################################################
# @determineSource()
# function determineSource()
#
# Paramters:
#     data: This will be a dict that has all of the information regarding all of the passwords that
#           are stored. Refer to Control Functions section header for description of this object.
#
# Returns: None
#
#     This function will determine the source of the input for the program. If there is any
# argument passed to the program then it determines if it is just an option for information request
# or if it is JSON data that needs to be processed. If there is no argument passed in then the
# it will set the source of the input to be from the terminal.
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
###################################################################################################


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
#     This section of functions are all functions that will be used to validate some sort of data
# or action.
###################################################################################################


###################################################################################################
# @checkFiles()
# function checkFiles()
#
# Parameters: None
#
# Returns: The data dictionary that has all of the passwords stored in the password file and the
#          fully qualified file name of the passwords file.
#
#     This function will read first check to see if there is a passwords file already stored in the
# directory of the program. If it does not exist then it creates the file. After it reads in the
# file it converts it into a dictionary and stores it as the "passwords" object in the data
# dictionary.
def checkFiles():
    global scriptDir

    # If passwords file does not exist, create it.
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
###################################################################################################


###################################################################################################
# @validateData()
# function validateData()
#
# Parameters:
#     source_data: This will be the incoming json data that is stored in the "data" dictionary that
#                  is initialized at the begining of the program. Refer to the Control Functions
#                  section of comments for explanation of how the data dictionary functions.
#
# Returns: None
def validateData(source_data):
    """
    The "action" key has to be checked before any actual JSON schema validation because its value
    will be used to determine which schema file to load to compare the incoming JSON data to.
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

    if not isValidAction(action, "json"):
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
###################################################################################################


###################################################################################################
# @isValidAction()
# function isValidAction()
#
# Parameters:
#     action: An integer representing the action to be taken.
#
#     source: The input source of the action. Default is "terminal".
#
# Returns: True if action is valid, False otherwise.
#
#     A validation function to dertmine of the requested action is in a valid range of actions. If
# the "source" argument is json then the actions range starts at 1 because action id of "0" is for
# exiting the program when running in the terminal.
def isValidAction(action, source="terminal"):
    rangeStart = 0

    if source == "json":
        rangeStart = 1
    # END IF

    if action not in range(rangeStart, 8):
        return False

    return True


# END isValidAction
###################################################################################################


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
#     This section of functions are all functions that will be used by other functions to offload
# some of the functionality to improve readability.
###################################################################################################

###################################################################################################
# @validateJsonFile()
# Helper of function determineSource()
# function validateJsonFile()
#
# Parameters:
#     fileName: The name of the file to validate.
#
# Returns: The data from the json file that will be treated as "source_data" of the program.
#
#     This function will read the json file and will simply just make sure that the file exists and
# that a valid json object could be decoded from it.
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
###################################################################################################


###################################################################################################
# @isValidSchemaId()
# Helper of function determineSource()
# function isValidSchemaId()
#
# Parameters:
#     schema_id: The id of the schema to check against.
#
# Returns: True if schema_id is valid, False otherwise.
#
#     This function checks the schema_id passed to it and sees if it would actually be a valid
# action as the schema_id will correalte with the action that the id would be tied to. So if
# the schema_id is the same as the integer value for perfroming the addPassword action then
# the schema file for addPassword will be displayed.
def isValidSchemaId(schema_id):
    action = schema_id

    try:
        action = int(action)

        if isValidAction(action, "json"):
            return True
        # END IF
    except ValueError as e:
        pass
    # END TRY

    # If execution reaches this point then something has gone wrong so print messsage.
    printMsg("Invalid value {} for schemaID. Use -i flag for options".format(action), "red")

    return False


#END isValidSchemaId() DEF
###################################################################################################


###################################################################################################
# @encryptDetails()
# Helper of function addPassword()
# function encryptDetails()
#
# Parameters:
#     details: The list of details that are to be encrypted if any of the list items are marked to
#              have any part of them encrypted.
#
#     cipher_suite: The cipher object used for encryption.
#
# Returns: Does not return anything. Since the list is passed by reference it can be modified in
#          place and the changes will be reflected in the place it was originally called in.
#
#     This function will be used in the addPassword() function. It will take the list of details
# obtained and then encrypt any parts of that contain the prefix "enc:|:". An example is below:
#
#     Before encryption: detials = ["Details string 1 with password enc:|:welcome123"]
#     After encryption: details = ["Details string 1 with password encrypted:gAAAAABcGpCOiUZnH"]
def encryptDetails(details, cipher_suite):
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
###################################################################################################


###################################################################################################
# @decryptDetails()
# Helper of function dumpDecryptedPasswords()
# function decryptDetails()
#
# Parameters:
#     details: The list of details that are to be decrypted if any of the list items are marked to
#              have any part of them decrypted.
#
#     cipher_suite: The cipher object used for decryption.
#
# Returns: List of all details decrypted that were marked for decryption.
#
#     This function will be used in the dumpDecryptedPasswords() function. It will take the list of details
#     obtained and then decrypt any parts of that contain the prefix "encrypted:". An example is below:
#
#     Before decryption: details = ["Details string 1 with password encrypted:gAAAAABcGpCOiUZnH"]
#     After decryption: detials = ["Details string 1 with password enc:|:welcome123"]
def (details, cipher_suite):
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
###################################################################################################


###################################################################################################
# @gatherPasswordInfo()
# Helper of function addPassword()
def gatherPasswordInfo(data, cipher_suite):
    pwUserName = ""
    pwVal = ""
    pwLabel = ""
    pwURL = ""
    pwDesc = ""
    pwDetails = ""
    pwInfo = ()

    if data["source"] == "json":
        pwInfo = getDataFromJSON(data, cipher_suite)
    else:
        pwInfo = getDataFromTerminal(data, cipher_suite)
    # END IF

    return pwInfo


# END gatherPasswordInfo() DEF


# @getDataFromJSON()
# Helper of function gatherPasswordInfo()
def getDataFromJSON(data, cipher_suite):
    passwords = data["passwords"]

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

    return (pwUserName, pwVal, pwLabel, pwURL, pwDesc, pwDetails)


# END getDataFromJSON() DEF


# @getDataFromTerminal()
# Helper of function gatherPasswordInfo()
def getDataFromTerminal(data, cipher_suite):
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
        printMsg("\nInvalid response \"{}\".".format(mirrorOtherLabel), "red")
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

    return (pwUserName, pwVal, pwLabel, pwURL, pwDesc, pwDetails)


# END getDataFromTerminal() DEF


# @processSchemaError()
# Helper of function validateData()
def processSchemaError(error, source_data):
    errInfo = error._contents()
    errValidator = errInfo["validator"]
    errPath = errInfo["path"]
    errPath.appendleft("root")
    errMsg = errInfo["message"]
    message = ""

    if errValidator == "required":
        message = getRequiredKeyMissingErrMessage(errMsg, errPath, source_data)
    elif errValidator == "type":
        message = getWrongTypeErrMessage(errInfo, errPath, source_data)
    else:
        printMsg(error)
        sys.exit(1)
    # END IF

    message = message + json.dumps(source_data, indent = 4)

    printMsg(message, "red")

    sys.exit(1)


# END processSchemaError() DEF


# @getRequiredKeyMissingErrMessage()
# Helper of function processSchemaError()
def getRequiredKeyMissingErrMessage(errMsg, errPath, currObj):
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

    return message

# END getRequiredKeyMissingErrMessage() DEF


# @getgetWrongTypeErrMessage()
# Helper of function processSchemaError()
def getWrongTypeErrMessage(errInfo, errPath, currObj):
    dataTypes = {
        type(""): "string",
        type(1): "integer",
        type(True): "boolean",
        type(1.23): "number",
        type([]): "list",
        type({}): "object"
    }

    for prop in list(errPath)[1:-1]:
        if prop in currObj.keys():
            currObj = currObj[prop]
        # END IF
    # END

    issueKey = list(errPath)[-1]
    expectedType = errInfo["validator_value"].replace("u'", "").replace("'", "")
    recievedType = dataTypes[type(currObj[issueKey])]
    message = "\nKey \"{}\" is wrong type in incoming JSON data".format(issueKey)
    message = message + "\nExpected type({}), got type({})".format(expectedType, recievedType)
    message = message + "\nJSON Path of key: {}".format(".".join(errPath))
    message = message + "\nIncoming JSON: \n"

    issueLine = "{} (wrong type got [{}], expected [{}]) <---"
    issueLine = issueLine.format(currObj[issueKey],  recievedType, expectedType)

    currObj[issueKey] = issueLine

    return message


# END getWrongTypeErrMessage() DEF


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

# @printMsg()
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
