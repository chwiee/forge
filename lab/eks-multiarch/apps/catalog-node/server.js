// catalog-node: express API pinned to old versions on purpose.
// lodash 4.17.11 -> CVE-2019-10744 (prototype pollution in defaultsDeep, CRITICAL,
// fixed in 4.17.12). The forge CVE gate must block the push.
const express = require('express');
const morgan = require('morgan');
const _ = require('lodash');
const os = require('os');

const app = express();
app.use(express.json());
app.use(morgan('tiny'));

const products = [
  { id: 1, name: 'keyboard', price: 49.9, tags: ['hardware'] },
  { id: 2, name: 'mouse', price: 19.9, tags: ['hardware'] },
  { id: 3, name: 'ide license', price: 99.0, tags: ['software'] },
];

app.get('/healthz', (_req, res) => res.send('ok'));

app.get('/info', (_req, res) =>
  res.json({ app: 'catalog-node', arch: process.arch, node: process.version, pod: os.hostname() }));

app.get('/products', (req, res) => {
  const sorted = _.sortBy(products, req.query.sort || 'id');
  res.json(req.query.tag ? _.filter(sorted, (p) => p.tags.includes(req.query.tag)) : sorted);
});

// The vulnerable call path: merging user-controlled JSON into defaults.
app.post('/products/search', (req, res) => {
  const opts = _.defaultsDeep({}, req.body, { limit: 10, sort: 'id' });
  res.json(_.take(_.sortBy(products, opts.sort), opts.limit));
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`catalog-node listening on :${port}`));
