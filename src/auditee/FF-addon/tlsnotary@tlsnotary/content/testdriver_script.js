var testdriver_exception;
try {

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

var auditeeBrowser;
var tlsnGetUrlsResponded = false;
var reqGetUrls;
var linkArray;
var tlsnCipherSuiteList;
var tlsnLinkIndex=0;
var tlsnCipherSuiteNames={"47":"security.ssl3.rsa_aes_128_sha","53":"security.ssl3.rsa_aes_256_sha",
	"4":"security.ssl3.rsa_rc4_128_md5","5":"security.ssl3.rsa_rc4_128_sha"};
var current_ciphersuite=''; //Testing only: used by script.js to tell backend which CS to use 

//copied from https://developer.mozilla.org/en-US/docs/Code_snippets/Progress_Listeners
const STATE_STOP = Ci.nsIWebProgressListener.STATE_STOP;
const STATE_IS_WINDOW = Ci.nsIWebProgressListener.STATE_IS_WINDOW;



var tgNB;

function getNotificationBoxText(){
    var win = Services.wm.getMostRecentWindow('navigator:browser'); //this is the target window
    tgNB = win.document.getElementById("global-notificationbox"); //global notification box area
    if (tgNB.currentNotification==null){ return false;}
    return tgNB.currentNotification.label;
}
//wait for the page to become secure before we press AUDIT
var tlsnLoadListener = {
	QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
										   "nsISupportsWeakReference"]),

	onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {},
	onLocationChange: function(aProgress, aRequest, aURI) {},
	onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
	onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
	onSecurityChange: function(aWebProgress, aRequest, aState)
	 {
        // check if the state is secure or not
        if(aState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
        {
			gBrowser.removeProgressListener(this);
			//begin recording as soon as the page turns into https, but not immediately, because
			//send_certificate request must go out first
			setTimeout(tlsnRecord, 1000);
        }    
    }
}


function tlsnSimulateClick(element) {
  var options = { // defaults
    clientX: 0, clientY: 0, button: 0,
    ctrlKey: false, altKey: false, shiftKey: false,
    metaKey: false, bubbles: true, cancelable: true
     // create event object:
  }, event = element.ownerDocument.createEvent("MouseEvents");

  // initialize the event object
  event.initMouseEvent('click', options.bubbles, options.cancelable,
                       element.ownerDocument.defaultView,  options.button,
                       options.clientX, options.clientY, options.clientX,
                       options.clientY, options.ctrlKey, options.altKey,
                       options.shiftKey, options.metaKey, options.button,
                       element);
  //prevent popup blocker
  prefs.setBoolPref("dom.disable_open_during_load", false);
  element.dispatchEvent(event);
}



function tlsnSendErrorMsg(errmsg){
    var reqSendError = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
    reqSendError.open("HEAD", "http://127.0.0.1:27777"+"/log_error?errmsg="+errmsg, true);
    reqSendError.send();
    return;
}


function tlsnInitTesting(){
    //required to allow silent close of all other tabs
    prefs.setBoolPref("browser.tabs.warnOnCloseOtherTabs", false);	
    //ask the back end for a list of websites to visit
    reqGetUrls = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
    reqGetUrls.onload = responseGetUrls;
    reqGetUrls.open("HEAD", "http://127.0.0.1:27777"+"/get_websites", true);
    reqGetUrls.send();
    //wait for response
    responseGetUrls(0);
}



function responseGetUrls(iteration){
    if (typeof iteration == "number"){
        if (iteration > 5){
            //use an alert rather than messaging the backend, since that's exactly what's failing
            alert("responseGetUrls timed out - python backend not responding. please investigate.");
            return;
        }
        if (!tlsnGetUrlsResponded) setTimeout(responseGetUrls, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
    tlsnGetUrlsResponded = true;
    var query = reqGetUrls.getResponseHeader("response");
    if (query !== "get_websites"){
        //use an alert rather than messaging the backend, since that's exactly what's failing
        alert("Error - wrong response query header: "+query);
        return;
    }
    var tlsnUrlList = reqGetUrls.getResponseHeader("url_list");
    var cipherSuiteList = reqGetUrls.getResponseHeader("cs_list");
    linkArray = tlsnUrlList.split(',');
    tlsnCipherSuiteList = cipherSuiteList.split(',');
    //urls received, start the p2p connection
    var btn = win.content.document.getElementById("start_button");
    tlsnSimulateClick(btn);
    //wait for status bar to show readiness.
    waitForP2PConnection();
}


//The main addon will put ERROR message on timeout
function waitForP2PConnection(){
	var helpmsg = getNotificationBoxText();
	
	if (helpmsg==false){
	    setTimeout(waitForP2PConnection,1000);
	    return;
	}
	
	if (helpmsg.startsWith("ERROR")){
		tlsnSendErrorMsg("Error received in browser: "+helpmsg +
						 "for site: "+linkArray[tlsnLinkIndex] +
						 " and cipher suite: "+tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex]]);
		return; //give up
	}
	if (!helpmsg.startsWith("Go to a page")){
		setTimeout(waitForP2PConnection, 1000);
		return;      
	}
	//give auditor time to run checks and start the receiving thread
	setTimeout(openNextLink, 2000);
}


function openNextLink(){
	if (tlsnLinkIndex >= linkArray.length){
        tlsnStopRecord();
        return;
    }
    current_ciphersuite = tlsnCipherSuiteList[tlsnLinkIndex];
    auditeeBrowser = gBrowser.addTab(linkArray[tlsnLinkIndex]);
    gBrowser.addProgressListener(tlsnLoadListener);
    gBrowser.removeAllTabsBut(auditeeBrowser);
    tgNB.currentNotification.label = "Loading page..."
    //FIXME we should use auditeeBrowser here instead of gBrowser
    //but for some reason the listener never triggers then
	waitForRecordingToFinish(0);
}


function waitForRecordingToFinish(iteration){
   var helpmsg = getNotificationBoxText();
    if (helpmsg.startsWith("ERROR")){
        tlsnSendErrorMsg("Error received in browser: "+helpmsg +
                         "for site: "+linkArray[tlsnLinkIndex] +
                         " and cipher suite: "+tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex]]);
        return; //give up
    }
    if (!(helpmsg.startsWith("Page decryption successful."))) {    
		if (iteration > 360){
			tlsnSendErrorMsg("Timed out waiting for page audit to finish"
							 +linkArray[tlsnLinkIndex]+" and cipher suite: "+
							 tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex]]);
			return;
		}
		setTimeout(waitForRecordingToFinish, 1000, ++iteration);
		return;
	}
	//the text is Page decryption successful. //give the addon some time to toggle off the offline mode
	tlsnLinkIndex++;
	setTimeout(openNextLink, 1000);
}


function tlsnRecord(){
    /* This code correctly gets the AUDIT.. button, but firing a click
    event at it does not trigger the callback. Hence we call startRecording() directly.
    var win = Services.wm.getMostRecentWindow('navigator:browser'); //this is the target window
    var btn = document.getElementsByAttribute("label","AUDIT THIS PAGE")[0]; //global notification box area
    tlsnSimulateClick(btn);
    */
    startRecording();
}


function tlsnStopRecord(){
    /* This code correctly gets the AUDIT.. button, but firing a click
    event at it does not trigger the callback. Hence we call startRecording() directly.
    var win = Services.wm.getMostRecentWindow('navigator:browser'); //this is the target window
    var btn = document.getElementsByAttribute("label","FINISH")[0]; //global notification box area
    tlsnSimulateClick(btn);
    */
    stopRecording();
    waitForSessionEnd(0);
}


function waitForSessionEnd(iteration){
	var helpmsg = getNotificationBoxText();
    if (!helpmsg.startsWith("Auditing session ended successfully")){
        if (iteration > 2000){
                tlsnSendErrorMsg("Timed out waiting for auditor to signal the verdict.");
                return;
         }
         setTimeout(waitForSessionEnd, 1000, ++iteration);
         return;
        }
	//the audit is fully completed. trigger the backend to do hash checks
    reqFinaliseTest = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
    //reqFinaliseTest.onload = responseGetKeyboardInput;
    reqFinaliseTest.open("HEAD", "http://127.0.0.1:27777"+"/end_test", true);
    reqFinaliseTest.send();
    //finished; there will be no response
}

} catch (e){
	testdriver_exception = e;
}

