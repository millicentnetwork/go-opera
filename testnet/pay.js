ftm.sendTransaction(
	{from: ftm.accounts[0], to: $1, value:  $2},
	function(err, transactionHash) {
        if (!err)
            console.log(transactionHash + " success");
    });
