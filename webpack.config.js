const path = require('path');

const baseConfig = {
  mode: 'production',
  devtool: false,
  entry: {
    iost: path.resolve(__dirname, './index.js')
  },
  resolve: {
    extensions: ['.js', '.ts'],
  },
}
const serverConfig = {
  ...baseConfig,
  target: 'node',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].node.js',
    library: 'IOST',
    libraryTarget: 'commonjs2',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        use: [
          {
            loader: "babel-loader",
            options: {
              presets: [
                ['@babel/env', {
                  targets: {
                    node: 6
                  }
                }]
              ],
              plugins: [
                "@babel/plugin-transform-async-to-generator"
              ],
            }
          },
        ]
      },
      {
        test: /\.ts$/,
        use: [
          {
            loader: 'ts-loader',
          }
        ],
      },
    ]
  },
}

const clientConfig = {
  ...baseConfig,
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].min.js',
    library: 'IOST',
    libraryTarget: 'umd',
    umdNamedDefine: true,
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        use: [
          {
            loader: "babel-loader",
            options: {
              plugins: [
                "@babel/plugin-transform-async-to-generator"
              ],
            }
          },
        ]
      },
      {
        test: /\.ts$/,
        use: [
          {
            loader: 'ts-loader',
          }
        ],
      },
    ]
  },
}

module.exports = [serverConfig, clientConfig]