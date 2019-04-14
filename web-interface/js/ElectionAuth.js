
var vote_contract;
var thresholdKey;
var publicVerifyParams;

function registerElection() {
    var numVoterPerRing = parseInt($("#numVoterPerRing").val());
    var numberVoterOptions = parseInt($("#numVotingOptions").val());
    var tParties = parseInt($('#tVoters').val());
    var nParties = parseInt($('#nVoters').val());
    alert("done");
    
}



function openFile(event) {
    
    var input = event.target;

    var reader = new FileReader();
    
    var n = document.getElementById('nVoters').value;
    var t = document.getElementById('tVoters').value;

    reader.onload = function() {
        var lines = reader.result.split("\n");

        if(lines.length - 2 == t) {

            var row = lines[0].split(",");
            thresholdKey = [new BigNumber(row[0]), new BigNumber(row[1])];
            publicVerifyParams = [];

            for(var i = 1; i < lines.length - 1; i++) {
                var row = lines[i].split(",");
                publicVerifyParams.push([new BigNumber(row[0]), new BigNumber(row[1])])
            }
        }
        else{
            input.value = "";
            alert('Problem with file');
        }
        
    }

    reader.readAsText(input.files[0]);
}






function startApp() {
    var contractAddress = "CONTRACT_ADDRESS";
    vote_Contract = new web3js.eth.Contract(contractABI, contractAddress);

    var accountInterval = setInterval(function() {
    // Check if account has changed
    if (web3.eth.accounts[0] !== userAccount) {
        userAccount = web3.eth.accounts[0];
        // Call a function to update the UI with the new account
}
}, 100);

};

window.addEventListener('load', function() {

// Checking if Web3 has been injected by the browser (Mist/MetaMask)
if (typeof web3 !== 'undefined') {
// Use Mist/MetaMask's provider
web3js = new Web3(web3.currentProvider);
BigNumber = web3.BigNumber;
} else {

    alert("Install Metamask");
// Handle the case where the user doesn't have Metamask installed
// Probably show them a message prompting them to install Metamask
}

startApp();

})


