//from https://raw.githubusercontent.com/dgutov/bmreplace/67ad019be480fc6b5d458dc886a2fb5364e92171/content/main.js

"use strict";

let prompts = Services.prompt;
let prefs = Services.prefs;

const TITLE = "Replace Bookmark",
      URL_NOT_SUPPORTED = "Sorry, the current page's URL is not supported.",
      RELATED_NOT_FOUND = "Sorry, no related bookmarks found.",
      ALREADY_BOOKMARKED = "The current page is already bookmarked.",
      SELECT_BOOKMARK = "Which bookmark do you want to replace?";

const NS_XUL = "http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul",
      PREFS_BRANCH = Services.prefs.getBranch("extensions.bmreplace.button-position."),
      PREF_TB = "toolbar",
      PREF_NEXT = "next-item",
      BUTTON_ID = "bmreplace-button";

let main = {
  action: function() {
	  //open a new tab or focus an existing one
	  var size = gBrowser.browsers.length;
	  var i;
	  for (i=0; i<size; i++){
		  if (gBrowser.browsers[i].contentWindow.location.href == "chrome://tlsnotary/content/auditee.html"){
			  gBrowser.selectTabAtIndex(i);
			  return;
		  }
	  }
	  //we get here when there was no tlsnotary tab open. Load a tab in foreground
	  gBrowser.loadOneTab("chrome://tlsnotary/content/auditee.html", null, null, null, false);  
  },
  
  /*
   * @return {toolbarId, nextItemId}
   */
  getPrefs: function() {
    try {
      return {
        toolbarId: PREFS_BRANCH.getCharPref(PREF_TB),
        nextItemId: PREFS_BRANCH.getCharPref(PREF_NEXT)
      };
    } catch(e) {
      return { // default position
        toolbarId: "nav-bar",
        nextItemId: "bookmarks-menu-button-container"
      };
    }
  },
  
  setPrefs: function(toolbarId, nextItemId) {
    PREFS_BRANCH.setCharPref(PREF_TB, toolbarId || "");
    PREFS_BRANCH.setCharPref(PREF_NEXT, nextItemId || "");
  }
};

