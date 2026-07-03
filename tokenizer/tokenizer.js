const fs = require('fs');
const path = require('path');

// Load vocab.txt (one token per line, index = line number)
const vocabLines = fs
  .readFileSync(path.join(__dirname, 'vocab.txt'), 'utf8')
  .split('\n')
  .map(l => l.trim())
  .filter(Boolean);

const tokenToId = {};
vocabLines.forEach((token, idx) => { tokenToId[token] = idx; });
const idToToken = vocabLines; // index → token

// Special token IDs (matched from your tokenizer_config.json)
const CLS_ID = 101;
const SEP_ID = 102;
const PAD_ID = 0;
const UNK_ID = 100;
const MAX_LEN = 128; // your model's max_length

// Basic BERT WordPiece-style tokenizer (lowercase + punctuation split)
function basicTokenize(text) {
  return text
    .toLowerCase()
    .replace(/([^a-z0-9])/g, ' $1 ') // split on non-alphanumeric
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

// WordPiece: split unknown words into subword pieces
function wordpieceTokenize(word) {
  if (tokenToId[word] !== undefined) return [word];

  const tokens = [];
  let start = 0;
  let isBad = false;

  while (start < word.length) {
    let end = word.length;
    let curSubstr = null;

    while (start < end) {
      const substr = (start > 0 ? '##' : '') + word.slice(start, end);
      if (tokenToId[substr] !== undefined) {
        curSubstr = substr;
        break;
      }
      end--;
    }

    if (curSubstr === null) { isBad = true; break; }
    tokens.push(curSubstr);
    start = end;
  }

  return isBad ? ['[UNK]'] : tokens;
}

/**
 * Tokenize a question into BERT input tensors
 * Format: [CLS] question tokens [SEP] padded to MAX_LEN
 */
function tokenize(question) {
  const words = basicTokenize(question);
  const subwords = words.flatMap(w => wordpieceTokenize(w));

  // Build token IDs: [CLS] + subwords + [SEP]
  const tokens = [
    CLS_ID,
    ...subwords.map(t => tokenToId[t] ?? UNK_ID),
    SEP_ID,
  ];

  // Truncate if needed
  if (tokens.length > MAX_LEN) tokens.splice(MAX_LEN - 1, tokens.length - MAX_LEN, SEP_ID);

  const attentionMask = tokens.map(() => 1);
  const tokenTypeIds  = tokens.map(() => 0); // single sentence = all 0s

  // Pad to MAX_LEN
  while (tokens.length < MAX_LEN) {
    tokens.push(PAD_ID);
    attentionMask.push(0);
    tokenTypeIds.push(0);
  }

  return {
    inputIds:       BigInt64Array.from(tokens.map(BigInt)),
    attentionMask:  BigInt64Array.from(attentionMask.map(BigInt)),
    tokenTypeIds:   BigInt64Array.from(tokenTypeIds.map(BigInt)),
    shape: [1, MAX_LEN],
  };
}

module.exports = { tokenize };