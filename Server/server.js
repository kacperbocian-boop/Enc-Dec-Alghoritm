const express = require('express');
const cors = require('cors');

const app = express();
const port = 3050;

app.use(cors());
app.use(express.json());

app.use('/api', require('./Encoding/Encode'));
app.use('/api', require('./Encoding/Decode'));
app.use('/api', require('./Encryption/Encrypt'));
app.use('/api', require('./Encryption/Decrypt'));
app.use('/api', require('./Encryption/KeyPair'));

app.listen(port, () => {
  console.log(`Server uruchomiony: http://localhost:${port}`);
});