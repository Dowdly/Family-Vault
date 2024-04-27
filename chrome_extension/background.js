chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "saveToken" && request.token) {
        chrome.storage.local.set({ 'token': request.token }, () => {
            console.log("Token saved in local storage");
            sendResponse({ success: true });
        });
        return true; // Keep the message channel open for the async response
    }
});
