const multer = require('multer');

// Save uploads straight into the public folder so they can be linked directly.
module.exports = multer({ dest: 'public/uploads/' });
