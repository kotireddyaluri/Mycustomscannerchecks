from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array

GREP_STRING = ".postMessage("
GREP_STRING_BYTES = bytearray(GREP_STRING)

GREP_STRING1 = ".addEventListener"
GREP_STRING_BYTES1 = bytearray(GREP_STRING1)

JWT_Keys = "eyJ"
JWT_Keys_Bytes = bytearray(JWT_Keys)

JavaDeser_Keys="rO0AB"
JavaDeser_Keys_Bytes = bytearray(JavaDeser_Keys)

callbacks = None
helpers = None

class BurpExtender(IBurpExtender, IScannerCheck):
    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers
        # keep a reference to our callbacks object
        callbacks = this_callbacks

        # obtain an extension helpers object
        helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("MyCustomScannerChecks")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(postMessageSender())
        callbacks.registerScannerCheck(postMessageReceiver())
        callbacks.registerScannerCheck(Jwt_Token_res())
        callbacks.registerScannerCheck(Java_Deserlize_res())

        return

class postMessageSender(IScannerCheck):
    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES)
        if (len(matches) == 0):
            return None

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "HTML5-postMessage Detected",
            "The response contains the string: " + GREP_STRING,
            "Information")]

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # report the issue
        return None

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0


class postMessageReceiver(IScannerCheck):
    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES1)
        if (len(matches) == 0):
            return None

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "HTML5-postMessage Receiver Detected",
            "The response contains the string: " + GREP_STRING1,
            "Information")]

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # report the issue
        return None

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

class Jwt_Token_res(IScannerCheck):
    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        matches = self._get_matches(baseRequestResponse.getResponse(), JWT_Keys_Bytes)
        if (len(matches) == 0):
            return None

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "JWT Token Detected - Response",
            "The response contains the string: " + JWT_Keys,
            "Information")]

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # report the issue
        return None

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

class Java_Deserlize_res(IScannerCheck):
    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        matches = self._get_matches(baseRequestResponse.getResponse(), JavaDeser_Keys_Bytes)
        if (len(matches) == 0):
            return None

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "Java Deserialization Object detected - Response",
            "The response contains the string: " + JavaDeser_Keys,
            "Information")]

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # report the issue
        return None

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0


#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
