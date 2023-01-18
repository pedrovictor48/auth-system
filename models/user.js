const mongoose = require('mongoose');

const UserSchema = mongoose.Schema({
    userName: {type: String, unique: true},
    email: {type: String, unique: true},
    password: String,
    verified: Boolean,
});

exports.UserSchema = mongoose.model("user", UserSchema);