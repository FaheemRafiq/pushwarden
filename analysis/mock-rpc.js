const http = require('http');

const MALICIOUS_WALLET = '0xa322E5f3'.toLowerCase();
const FAKE_C2_IP = Buffer.from('127.0.0.1').toString('hex');
const FAKE_TX = {
  hash: '0x' + 'ab'.repeat(32),
  from: '0x' + '11'.repeat(20),
  to: '0xa322E5f3' + '00'.repeat(16),
  value: '0x' + FAKE_C2_IP,
  blockNumber: '0x1',
  input: '0x',
};

let currentBlock = 90000000;

function handleRpc(body) {
  const resp = { jsonrpc: '2.0', id: body.id };

  switch (body.method) {
    case 'eth_blockNumber':
      resp.result = '0x' + currentBlock.toString(16);
      break;

    case 'eth_getBlockByNumber':
      const blockNum = parseInt(body.params[0], 16);
      const txCount = (blockNum === currentBlock) ? 3 : 0;
      const txs = [];
      for (let i = 0; i < txCount; i++) {
        if (i === 1) {
          txs.push({
            ...FAKE_TX,
            hash: '0x' + 'cc'.repeat(32),
            blockNumber: '0x' + blockNum.toString(16),
          });
        } else {
          txs.push({
            hash: '0x' + 'dd'.repeat(32),
            from: '0x' + 'aa'.repeat(20),
            to: '0x' + 'bb'.repeat(20),
            value: '0x0',
            blockNumber: '0x' + blockNum.toString(16),
            input: '0x',
          });
        }
      }
      resp.result = {
        number: '0x' + blockNum.toString(16),
        transactions: body.params[1] ? txs : txs.map(t => t.hash),
      };
      break;

    case 'eth_getTransactionByHash':
      resp.result = FAKE_TX;
      break;

    case 'eth_getTransactionCount':
      resp.result = '0x1';
      break;

    case 'eth_gasPrice':
      resp.result = '0x3b9aca00';
      break;

    case 'eth_estimateGas':
      resp.result = '0x5208';
      break;

    case 'net_version':
      resp.result = '1';
      break;

    default:
      resp.result = null;
      resp.error = { code: -32601, message: `Method not mocked: ${body.method}` };
  }

  return resp;
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try {
      const parsed = JSON.parse(body);
      const response = handleRpc(parsed);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
      console.log(`[MOCK-RPC] ${parsed.method} -> ${JSON.stringify(response.result)?.substring(0, 100)}`);
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
  });
});

server.listen(8545, '0.0.0.0', () => {
  console.log('[MOCK-RPC] Ethereum RPC mock listening on port 8545');
  console.log(`[MOCK-RPC] Fake C2 wallet: ${FAKE_TX.to}`);
  console.log(`[MOCK-RPC] Current block: ${currentBlock}`);
});
