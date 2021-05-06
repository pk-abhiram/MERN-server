const { Schema, model } = require('mongoose');

const UserTokenSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
    },
    refreshToken: {
      type: [String],
      default: [],
    },
  },
  { timestamps: true }
);

module.exports = model('userToken', UserTokenSchema);
