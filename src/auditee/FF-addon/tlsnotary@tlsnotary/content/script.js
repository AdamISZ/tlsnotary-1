var script_exception;
try {	

var Cc = Components.classes;
var Ci = Components.interfaces;
var Cu = Components.utils;
var envvar = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("");

var bStartRecordingResponded = false;
var bStopRecordingResponded = false;
var bStopStartAudit = false;
var bIsRecordingSoftwareStarted = false; //we start the software only once
var reqStartRecording;
var reqStopRecording;
var reqStartAudit;
var tab_url_full = "";//full URL at the time when AUDIT* is pressed
var tab_url = ""; //the URL at the time when AUDIT* is pressed (only the domain part up to the first /)
var session_path = "";
var audited_browser; //the FF's internal browser which contains the audited HTML
var testingMode = false;
var headers="";
var dict_of_certs = {};
var dict_of_status = {};
var dict_of_httpchannels = {};

var port = envvar.get("FF_to_backend_port");
var decr_port = envvar.get("TLSNOTARY_AES_DECRYPTION_PORT");
//setting homepage should be done from here rather than defaults.js in order to have the desired effect. FF's quirk.
prefs.setCharPref("browser.startup.homepage", "chrome://tlsnotary/content/auditee.html");
Cu.import("resource://gre/modules/PopupNotifications.jsm");
Cu.import('resource://gre/modules/Services.jsm');

var win;
var gBrowser ;
var setTimeout ;
var btoa ;
var atob ;
var alert;


function init(){
	//wait for a window to appear
	let mustSleep = false;
	try{
		win = Cc['@mozilla.org/appshell/window-mediator;1']
					  .getService(Components.interfaces.nsIWindowMediator)
					  .getMostRecentWindow('navigator:browser');
					  
		if (win == null){
			mustSleep = true;
		}
		else if ( win.gBrowser == undefined || win.setTimeout == undefined || 
			win.btoa == undefined || win.atob == undefined || win.alert == undefined){
			mustSleep = true;
		}
	}
	catch (e) {
		mustSleep = true
	}
	if (mustSleep){
		//cannot use win.setTimeout, so using FF's built-in
		let timer = Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer);
		timer.initWithCallback({ notify: init }, 100, Ci.nsITimer.TYPE_ONE_SHOT);
		return;
	}
	//copy all those functions which belong in a Window object 
	//(and for which there are no counterparts in FF addons code yet)
	gBrowser = win.gBrowser;
	setTimeout = win.setTimeout;
	btoa = win.btoa;
	atob = win.atob;
	alert = win.alert;
	
	check_addon_mode();
	setPrefs();
	//start waiting
	setTimeout(startListening,500);
	pollEnvvar();
	
	if (envvar.get("TLSNOTARY_TEST") == "true"){
		setTimeout(tlsnInitTesting,3000);
		testingMode = true;
	}
}


var dsprops;
var ProfilePath;
var profile_dir;
var src_dir;
var py_dir;
var portsfile;
var filesdir;
var process;
var py_exe;
var auditee_py;
var arguments;
function check_addon_mode(){
	//**** get profile folder path ****
	dsprops = Cc['@mozilla.org/file/directory_service;1'].getService(Ci.nsIProperties);
	ProfilePath = dsprops.get("ProfD", Ci.nsIFile).path;
	//**** initialize file ****
	profile_dir = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	profile_dir.initWithPath(ProfilePath);
	//**** append each step in the path ****
	src_dir = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	py_dir = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	portsfile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	src_dir.initWithPath(ProfilePath);
	src_dir.append("extensions");
	src_dir.append("tlsnotary@tlsnotary");
	src_dir.append("src");

	py_dir.initWithPath(ProfilePath);
	py_dir.append("extensions");
	py_dir.append("tlsnotary@tlsnotary");
	py_dir.append("Python27");

	if (src_dir.exists()){
		filesdir = profile_dir.clone();
		filesdir.append("tlsnotary_files");
		if (! filesdir.exists()){
			filesdir.create(filesdir.DIRECTORY_TYPE, 0775);
			src_dir.copyTo(filesdir, null);
			py_dir.copyTo(filesdir, null);
		}
		var os = Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULRuntime).OS; 
		process = Cc['@mozilla.org/process/util;1'].getService(Ci.nsIProcess);
		py_exe = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		if (os == "WINNT"){
			py_exe = py_dir.clone();
			py_exe.append("python.exe");
		}
		else if (os == "Darwin"){
			py_exe.initWithPath("/Library/Frameworks/Python.framework/Verions/2.7/bin/python");
		}
		else {
			py_exe.initWithPath("/usr/bin/python");
		}
		process.init(py_exe);
		auditee_py = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		auditee_py = filesdir.clone();
		auditee_py.append("src");
		auditee_py.append("auditee");
		auditee_py.append("tlsnotary-auditee.py");
		arguments= [auditee_py.path,"mode=addon"] ; // command line arguments array
		portsfile.initWithPath(filesdir.path);
		portsfile.append("src");
		portsfile.append("auditee");
		portsfile.append("ports");
		//python will create these files
		if (portsfile.exists()){
			portsfile.remove(false);
		}
		process.run(false, arguments, arguments.length);
		//cannot use win.setTimeout, so using FF's built-in
		//let timer = Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer);
		//timer.initWithCallback({ notify: checkports }, 1000, Ci.nsITimer.TYPE_ONE_SHOT);
		setTimeout(checkports, 1000);
		Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).set("TLSNOTARY_ADDON_MODE", "true");
	}
}


var ports_str;
var fstream;
var sstream;
function checkports(){
	if (portsfile.exists() && portsfile.isReadable()){
		fstream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(Ci.nsIFileInputStream);
		sstream = Cc["@mozilla.org/scriptableinputstream;1"].createInstance(Ci.nsIScriptableInputStream);
		fstream.init(portsfile, -1, 0, 0);
		sstream.init(fstream);
		ports_str = sstream.read(4096);
		port = ports_str.split(" ")[0];
		//set the envvar for auditee.html to know the port
		Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).set("FF_to_backend_port", port);
		decr_port = ports_str.split(" ")[1];
	}
	else {
		//let timer = Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer);
		//timer.initWithCallback({ notify: checkports }, 1000, Ci.nsITimer.TYPE_ONE_SHOT);
		setTimeout(checkports, 1000);
	}
}


function popupShow(text) {
	var notify  = new PopupNotifications(gBrowser,
                    win.document.getElementById("notification-popup"),
                    win.document.getElementById("notification-popup-box"));
	notify.show(gBrowser.selectedBrowser, "tlsnotary-popup", text,
	null, /* anchor ID */
	{
	  label: "Close this notification",
	  accessKey: "C",
	  callback: function() {},
	},
	null  /* secondary action */
	);
}

/*Show the notification with default buttons (usebutton undefined), 'AUDIT' and 'FINISH'
or with just the AUDIT button (usebutton true or truthy) or no buttons (usebutton false) */
function notBarShow(text,usebutton){
    var _gNB = win.document.getElementById("global-notificationbox"); //global notification box area
    _gNB.removeAllNotifications();
    var buttons;
    if (typeof(usebutton)==='undefined'){
    //Default: show both buttons
	buttons = [{
	    label: 'AUDIT THIS PAGE',
	    popup: null,
	    callback: startRecording
	},
	{
	    label: 'FINISH',
	    accessKey: null,
	    popup: null,
	    callback: stopRecording
	    }];
    }
    else if (usebutton===false){
	buttons = null;
    }
    else{
	buttons = [{
	    label: 'AUDIT THIS PAGE',
	    accessKey: "U",
	    popup: null,
	    callback: startRecording
	}];
    }
	const priority = _gNB.PRIORITY_INFO_MEDIUM;
	_gNB.appendNotification(text, 'tlsnotary-box',
			     'chrome://tlsnotary/content/icon.png',
			      priority, buttons);
}


//poll the env var to see if IRC started so that we can display a help message on the addon toolbar
//We do this from here rather than from auditee.html to make it easier to debug
var prevMsg = "";
function pollEnvvar(){
	var msg = envvar.get("TLSNOTARY_MSG");
	if (msg != prevMsg) {
		prevMsg = msg;
		notBarShow(msg,false);
	}
	var envvarvalue = envvar.get("TLSNOTARY_IRC_STARTED");
	if (!envvarvalue.startsWith("true")) {
		setTimeout(pollEnvvar, 1000);
		return;
	}
	//else if envvar was set, init all global vars
	
	var tmode = envvarvalue.charAt(envvarvalue.length -1)
	if (tmode=='0'){
	popupShow("The self testing audit connection is established. You may now open a new tab and go to a webpage. Please follow the instructions on the status bar below. ");
	}
	else {
	popupShow("The connection to the auditor has been established. You may now open a new tab and go to a webpage. Please follow the instructions on the status bar below.");
	}
	
	notBarShow("Go to a page and press AUDIT THIS PAGE. Then wait for the page to reload automatically.",true);
	if (decr_port != ""){
		startDecryptionProcess();}
}


function startListening(){
//from now on, we will check the security status of all loaded tabs
//and store the security status and certificate fingerprint in a lookup table
//indexed by the url. Doing this immediately allows the user to start
//loading tabs before the peer negotiation is finished.
    gBrowser.addProgressListener(myListener);
}


function startRecording(){
    audited_browser = gBrowser.selectedBrowser;
    tab_url_full = audited_browser.contentWindow.location.href;
    
    //remove hashes - they are not URLs but are used for internal page mark-up
    sanitized_url = tab_url_full.split("#")[0];
    
    if (!sanitized_url.startsWith("https://")){
	var btn = win.document.getElementsByAttribute("label","FINISH")[0]; //global notification box area
	errmsg="ERROR You can only audit pages which start with https://";
	if (typeof(btn)==='undefined'){
	    notBarShow(errmsg,true);
	}
	else{
	    notBarShow(errmsg);
	}
	return;
    }
    if (dict_of_status[sanitized_url] != "secure"){
	alert("The page does not have a valid SSL certificate. Try to refresh the page and then press AUDIT THIS PAGE.");
	notBarShow("Go to a page and press AUDIT THIS PAGE. Then wait for the page to reload automatically.");
	return;
    }
    
    //passed tests, secure, grab headers, update status bar and start audit:
    var x = sanitized_url.split('/');
    x.splice(0,3);
    tab_url = x.join('/');
	
    var httpChannel = dict_of_httpchannels[sanitized_url]
	headers = "";
	headers += httpChannel.requestMethod + " /" + tab_url + " HTTP/1.1" + "\r\n";
	httpChannel.visitRequestHeaders(function(header,value){
                                  headers += header +": " + value + "\r\n";});
    if (httpChannel.requestMethod == "GET"){
		headers += "\r\n";
	}       
    if (httpChannel.requestMethod == "POST"){
		//for POST, extra "\r\n" is already included in uploaddata (see below) to separate http header from http body 
		var uploadChannel = httpChannel.QueryInterface(Ci.nsIUploadChannel);
		var uploadChannelStream = uploadChannel.uploadStream;
		uploadChannelStream.QueryInterface(Ci.nsISeekableStream);                 
		uploadChannelStream.seek(0,0);                               
		var stream = Cc['@mozilla.org/scriptableinputstream;1'].createInstance(Ci.nsIScriptableInputStream);
		stream.init(uploadChannelStream);
		var uploaddata = stream.read(stream.available());
		//FF's uploaddata contains Content-Type and Content-Length headers + '\r\n\r\n' + http body
		headers += uploaddata;
	}
    startAudit(sanitized_url);
}


function buildBase64DER(chars){
    var result = "";
    for (i=0; i < chars.length; i++)
        result += String.fromCharCode(chars[i]);
    return btoa(result);
}


function startAudit(urldata){
    notBarShow("Audit is underway, please be patient.",false);
    reqStartAudit = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
    reqStartAudit.onload = responseStartAudit;
    var cert = dict_of_certs[urldata];
    var len = new Object();
    var rawDER = cert.getRawDER(len);
    var b64DERCert = buildBase64DER(rawDER);    
    var b64headers = btoa(headers); //headers is a global variable
    var ciphersuite = ''
    if (testingMode == true){
		ciphersuite = current_ciphersuite; //<-- global var from testdriver_script.js
	}
    reqStartAudit.open("HEAD", "http://127.0.0.1:"+port+"/start_audit?b64dercert="+b64DERCert+
		"&b64headers="+b64headers+"&ciphersuite="+ciphersuite, true);
	reqStartAudit.timeout = 0; //no timeout
    reqStartAudit.send();
    responseStartAudit(0);	
}


function responseStartAudit(iteration){
    if (typeof iteration == "number"){
        if (iteration > 200){
	    notBarShow("ERROR: responseStartAudit timed out",false);
            return;
        }
        if (!bStopStartAudit) setTimeout(responseStartAudit, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStopStartAudit = true;
    var query = reqStartAudit.getResponseHeader("response");
    var status = reqStartAudit.getResponseHeader("status");
   	if (query != "start_audit"){
		notBarShow("ERROR Internal error. Wrong response header: " +query,false);
        return;
    }
    if (status != "success"){
        if (testingMode == true) {
	    notBarShow("ERROR Received an error message: " + status);
            return; //failure to find HTML is considered a fatal error during testing
        }
        notBarShow("ERROR Received an error message: " + status + ". Page decryption FAILED. Try pressing AUDIT THIS PAGE again",true);
        
        return;
    }

    //else successful response
    b64_html_paths = reqStartAudit.getResponseHeader("html_paths");
    html_paths_string = atob(b64_html_paths);

    html_paths = html_paths_string.split("&").filter(function(e){return e});

    //in new tlsnotary, perhaps there cannot be more than one html,
    //but kept in a loop just in case
    go_offline_for_a_moment(); //prevents loading images from cache
    for (var i=0; i<html_paths.length; i++){
        var browser = gBrowser.getBrowserForTab(gBrowser.addTab(html_paths[i]));
    }

    notBarShow("Page decryption successful. Press FINISH or go to another page and press AUDIT THIS PAGE");
    
}


function go_offline_for_a_moment(){
	win.document.getElementById("goOfflineMenuitem").doCommand()
	setTimeout(function(){
			win.document.getElementById("goOfflineMenuitem").doCommand()
		}, 1000)
}


function stopRecording(){
    notBarShow("Preparing the data to be sent to the auditor",false);
    reqStopRecording = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
    reqStopRecording.onload = responseStopRecording;
    reqStopRecording.open("HEAD", "http://127.0.0.1:"+port+"/stop_recording", true);
    reqStopRecording.send();
    responseStopRecording(0);
}


function responseStopRecording(iteration){
    if (typeof iteration == "number"){
		var timeout = 100;
		if (testingMode) timeout = 2000;
        if (iteration > timeout){
	    notBarShow("ERROR responseStopRecording timed out ",false);
            return;
        }
        if (!bStopRecordingResponded) setTimeout(responseStopRecording, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStopRecordingResponded = true;
    var query = reqStopRecording.getResponseHeader("response");
    var status = reqStopRecording.getResponseHeader("status");
    session_path = reqStopRecording.getResponseHeader("session_path");
	
    if (query != "stop_recording"){
		notBarShow("ERROR Internal error. Wrong response header: "+query,false);
        return;
    }
	if (status != "success"){
		notBarShow("ERROR Received an error message: " + status,false);
		return;
	}

	popupShow("Congratulations. The auditor has acknowledged successful receipt of your audit data. You may now close the browser");
	notBarShow("Auditing session ended successfully",false);
	return;
}


function dumpSecurityInfo(channel,urldata) {
    // Do we have a valid channel argument?
    if (! channel instanceof  Ci.nsIChannel) {
        console.log("No channel available\n");
        return;
    }
    var secInfo = channel.securityInfo;
    // Print general connection security state
    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
        secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
        // Check security state flags
	latest_tab_sec_state = "uninitialised";
        if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) == Ci.nsIWebProgressListener.STATE_IS_SECURE)
            latest_tab_sec_state = "secure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) == Ci.nsIWebProgressListener.STATE_IS_INSECURE)
            latest_tab_sec_state = "insecure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) == Ci.nsIWebProgressListener.STATE_IS_BROKEN)
            latest_tab_sec_state = "unknown";
	
	//remove hashes - they are not URLs but are used for internal page mark-up
	sanitized_url = urldata.split("#")[0];
	dict_of_status[sanitized_url] = latest_tab_sec_state;
	dict_of_httpchannels[sanitized_url]  = channel.QueryInterface(Ci.nsIHttpChannel);
	
    }
    else {
        console.log("\tNo security info available for this channel\n");
    }
    // Print SSL certificate details
    if (secInfo instanceof Ci.nsISSLStatusProvider) {
      var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;
      dict_of_certs[sanitized_url] = cert;
      //send the cert immediately to backend to prepare encrypted PMS
	  send_cert_to_backend(cert);
    }
}


function send_cert_to_backend(cert){
    var len = new Object();
    var rawDER = cert.getRawDER(len);
    var b64DERCert = buildBase64DER(rawDER);    
	var reqSendCertificate = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
    reqSendCertificate.open("HEAD", "http://127.0.0.1:"+port+"/send_certificate?"+b64DERCert, true);
    reqSendCertificate.send();
    //we don't care about the response
}


var	myListener =
{
    QueryInterface: function(aIID)
    {
        if (aIID.equals(Ci.nsIWebProgressListener) ||
           aIID.equals(Ci.nsISupportsWeakReference) ||
           aIID.equals(Ci.nsISupports))
            return this;
        throw Components.results.NS_NOINTERFACE;
    },
    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) { },
    onLocationChange: function(aProgress, aRequest, aURI) { },
    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) { },
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) { },
    onSecurityChange: function(aWebProgress, aRequest, aState) 
    {
        // check if the state is secure or not
        if(aState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
        {
            // this is a secure page, check if aRequest is a channel,
            // since only channels have security information
            if (aRequest instanceof Ci.nsIChannel)
            {
                dumpSecurityInfo(aRequest,gBrowser.selectedBrowser.contentWindow.location.href);           
            }
        }    
    }
}


var reqReadyToDecrypt;
var bStopReadyToDecrypt = false;
function startDecryptionProcess(){
	reqReadyToDecrypt = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
	reqReadyToDecrypt.onload = responseReadyToDecrypt;
	reqReadyToDecrypt.open("HEAD", "http://127.0.0.1:"+decr_port+"/ready_to_decrypt", true);
	reqReadyToDecrypt.send();
	setTimeout(responseReadyToDecrypt, 0, 0);
}

function responseReadyToDecrypt(iteration){
    if (typeof iteration == "number" || iteration == undefined){
		//we dont want to time out because this is an endless loop        
        if (!bStopReadyToDecrypt) setTimeout(responseReadyToDecrypt, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStopReadyToDecrypt = true;
    var query = reqReadyToDecrypt.getResponseHeader("response");
    var b64ciphertext = reqReadyToDecrypt.getResponseHeader("ciphertext");
    var b64key = reqReadyToDecrypt.getResponseHeader("key");
    var b64iv = reqReadyToDecrypt.getResponseHeader("iv");
   	if (query != "ready_to_decrypt"){
		alert(iteration);
		notBarShow("ERROR Internal error. Wrong response header: " +query,false);
        return;
    }
    var b64cleartext = aes_decrypt(b64ciphertext, b64key, b64iv);
    bStopReadyToDecrypt = false;
    var req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
    req.open("HEAD", "http://127.0.0.1:"+decr_port+"/cleartext="+b64cleartext, true);
	req.send();
	reqReadyToDecrypt.open("HEAD", "http://127.0.0.1:"+decr_port+"/ready_to_decrypt", true);
	reqReadyToDecrypt.timeout = 0; //no timeout
	reqReadyToDecrypt.send();
	responseReadyToDecrypt(0);
}

function aes_decrypt(b64ciphertext, b64key, b64IV){
	var cipherParams = CryptoJS.lib.CipherParams.create({
	ciphertext: CryptoJS.enc.Base64.parse(b64ciphertext)
	});
	var key = CryptoJS.enc.Base64.parse(b64key)
	var IV = CryptoJS.enc.Base64.parse(b64IV)
	var decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv: IV })
	var b64decrypted = decrypted.toString(CryptoJS.enc.Base64)
	return b64decrypted;
}


function setPrefs(){
//We only need RSA ciphers AES128/256/RC4MD5/RC4SHA 
prefs.setBoolPref("security.ssl3.dhe_dss_aes_128_sha", false);
prefs.setBoolPref("security.ssl3.dhe_dss_aes_256_sha",false);
prefs.setBoolPref("security.ssl3.dhe_dss_camellia_128_sha",false);
prefs.setBoolPref("security.ssl3.dhe_dss_camellia_256_sha",false);
prefs.setBoolPref("security.ssl3.dhe_dss_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.dhe_rsa_aes_128_sha",false);
prefs.setBoolPref("security.ssl3.dhe_rsa_aes_256_sha",false);
prefs.setBoolPref("security.ssl3.dhe_rsa_camellia_128_sha",false);
prefs.setBoolPref("security.ssl3.dhe_rsa_camellia_256_sha",false);
prefs.setBoolPref("security.ssl3.dhe_rsa_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_ecdsa_aes_128_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_ecdsa_aes_256_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_ecdsa_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_ecdsa_rc4_128_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_rsa_aes_128_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_rsa_aes_256_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_rsa_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.ecdh_rsa_rc4_128_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",false);
prefs.setBoolPref("security.ssl3.ecdhe_ecdsa_aes_128_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_ecdsa_aes_256_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",false);
prefs.setBoolPref("security.ssl3.ecdhe_rsa_aes_128_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_rsa_aes_256_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_rsa_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.ecdhe_rsa_rc4_128_sha",false);
prefs.setBoolPref("security.ssl3.rsa_aes_128_sha",true);
prefs.setBoolPref("security.ssl3.rsa_aes_256_sha",true);
prefs.setBoolPref("security.ssl3.rsa_camellia_128_sha",false);
prefs.setBoolPref("security.ssl3.rsa_camellia_256_sha",false);
prefs.setBoolPref("security.ssl3.rsa_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.rsa_fips_des_ede3_sha",false);
prefs.setBoolPref("security.ssl3.rsa_rc4_128_md5",true);
prefs.setBoolPref("security.ssl3.rsa_rc4_128_sha",true);
prefs.setBoolPref("security.ssl3.rsa_seed_sha",false);
prefs.setIntPref("security.tls.version.max",1); // use only TLS 1.0

prefs.setBoolPref("security.enable_tls_session_tickets",false);

//tshark can't dissect spdy. websockets may cause unexpected issues
prefs.setBoolPref("network.http.spdy.enabled",false);
prefs.setBoolPref("network.http.spdy.enabled.v2",false);
prefs.setBoolPref("network.http.spdy.enabled.v3",false);
prefs.setBoolPref("network.websocket.enabled",false);
//no cache should be used
prefs.setBoolPref("browser.cache.disk.enable", false);
prefs.setBoolPref("browser.cache.memory.enable", false);
prefs.setBoolPref("browser.cache.disk_cache_ssl", false);
prefs.setBoolPref("network.http.use-cache", false);
}

//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
init();

} catch (e){
	script_exception = e;
}
