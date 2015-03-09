//from https://raw.githubusercontent.com/dgutov/bmreplace/67ad019be480fc6b5d458dc886a2fb5364e92171/bootstrap.js

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/AddonManager.jsm");

var self = this, icon;

function include(addon, path) {
  Services.scriptloader.loadSubScript(addon.getResourceURI(path).spec, self);
}

function $(node, childId) {
  if (node.getElementById) {
    return node.getElementById(childId);
  } else {
    return node.querySelector("#" + childId);
  }
}

function loadIntoWindow(window) {
  if (!window) return;
  
  let doc = window.document;
  let toolbox = $(doc, "navigator-toolbox");
  
  if (toolbox) { // navigator window
    // add to palette
    let button = doc.createElement("toolbarbutton");
    button.setAttribute("id", BUTTON_ID);
    button.setAttribute("label", "Replace Bookmark");
    button.setAttribute("class", "toolbarbutton-1 chromeclass-toolbar-additional");
    button.setAttribute("tooltiptext", "Replace an existing bookmark");
    button.style.listStyleImage = "url(" + icon + ")";
    button.addEventListener("command", main.action, false);
    toolbox.palette.appendChild(button);
    
    // move to saved toolbar position
    let {toolbarId, nextItemId} = main.getPrefs(),
        toolbar = toolbarId && $(doc, toolbarId);
    if (toolbar) {
      let nextItem = $(doc, nextItemId);
      toolbar.insertItem(BUTTON_ID, nextItem &&
                         nextItem.parentNode.id == toolbarId &&
                         nextItem);
    }
    window.addEventListener("aftercustomization", afterCustomize, false);
    
    // add hotkey
    let replaceKey = doc.createElementNS(NS_XUL, "key");
    replaceKey.setAttribute("id", "RB:Replace");
    replaceKey.setAttribute("key", "D");
    replaceKey.setAttribute("modifiers", "accel,alt");
    replaceKey.setAttribute("oncommand", "void(0);");
    replaceKey.addEventListener("command", main.action, true);
    $(doc, "mainKeyset").appendChild(replaceKey);
  }
}

function afterCustomize(e) {
  let toolbox = e.target;
  let button = $(toolbox.parentNode, BUTTON_ID);
  let toolbarId, nextItemId;
  if (button) {
    let parent = button.parentNode,
        nextItem = button.nextSibling;
    if (parent && parent.localName == "toolbar") {
      toolbarId = parent.id;
      nextItemId = nextItem && nextItem.id;
    }
  }
  main.setPrefs(toolbarId, nextItemId);
}

function unloadFromWindow(window) {
  if (!window) return;
  let doc = window.document;
  let button = $(doc, BUTTON_ID) ||
    $($(doc, "navigator-toolbox").palette, BUTTON_ID);
  button && button.parentNode.removeChild(button);
  window.removeEventListener("aftercustomization", afterCustomize, false);
}

function eachWindow(callback) {
  let enumerator = Services.wm.getEnumerator("navigator:browser");
  while (enumerator.hasMoreElements()) {
    let win = enumerator.getNext();
    if (win.document.readyState === "complete") {
      callback(win);
    } else {
      runOnLoad(win, callback);
    }
  }
}

function runOnLoad (window, callback) {
  window.addEventListener("load", function() {
    window.removeEventListener("load", arguments.callee, false);
    callback(window);
  }, false);
}

function windowWatcher (subject, topic) {
  if (topic === "domwindowopened") {
    runOnLoad(subject, loadIntoWindow);
  }
}

function startup(data, reason) AddonManager.getAddonByID(data.id, function(addon) {
  include(addon, "content/button.js");
  include(addon, "content/script.js");
  include(addon, "content/testdriver_script.js");
  include(addon, "content/core.js");
  include(addon, "content/enc-base64.js");
  include(addon, "content/cipher-core.js");
  include(addon, "content/aes.js");

  icon = addon.getResourceURI("content/icon.png").spec;
  
  // existing windows
  eachWindow(loadIntoWindow);
  
  // new windows
  Services.ww.registerNotification(windowWatcher);
});

function shutdown(data, reason) {
  Services.ww.unregisterNotification(windowWatcher);
  eachWindow(unloadFromWindow);
}

function install(data,reason) {
	//open in foreground. Need to sleep a little, otherwise the page wont be ready
	let win = Cc['@mozilla.org/appshell/window-mediator;1']
				  .getService(Components.interfaces.nsIWindowMediator)
					  .getMostRecentWindow('navigator:browser');
	win.setTimeout(function(){
		win.gBrowser.loadOneTab("chrome://tlsnotary/content/auditee.html", null, null, null, false);
	}, 1000);
}

function uninstall(data,reason) {
	//**** get profile folder path ****
	let dsprops = Cc['@mozilla.org/file/directory_service;1'].getService(Ci.nsIProperties);
	let ProfilePath = dsprops.get("ProfD", Ci.nsIFile).path;
	//**** initialize file ****
	let files_dir = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	files_dir.initWithPath(ProfilePath);
	files_dir.append("tlsnotary_files");
	if (files_dir.exists()){
		fiels_dir.remove(true);
	}
}
