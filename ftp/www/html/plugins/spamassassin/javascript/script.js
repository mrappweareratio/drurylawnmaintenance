function PopUp(popupURL) {
  this.url  = popupURL;
  this.name = 'popup_help';
}

PopUp.prototype.show = function() { 
  var featuresString = 'height=315,width=500,resizable=yes';
  window.open(this.url, this.name, featuresString);
}

function enableAutoLearn() {
  var disabled = document.getElementById("noBayes").checked;

  document.getElementById("yesLearn").disabled = disabled;
  document.getElementById("noLearn").disabled  = disabled;
}

function switchUser(userName) {
  window.location = "config.php?mode=local&user=" + userName;
}
