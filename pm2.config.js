const cfg = require('cfg');
const path = require('path');

module.exports = {
  apps: [
    {
      name: "easydarwin",
      script: 'app.js',
      cwd: __dirname,
      env: {
        NODE_PATH: __dirname,
        NODE_ENV: 'production'
      },
      watch: false,
      autorestart: false,
      error_file: path.resolve(cfg.dataDir, "logs/easydarwin.log"),
      out_file: path.resolve(cfg.dataDir, "logs/easydarwin.log")
    }
  ]
};
