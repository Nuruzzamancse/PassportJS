const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/passportapp');
const bcrypt = require('bcryptjs');

// User Schema
const UserSchema = mongoose.Schema({
    name: {
        type: String
    },
    username: {
        type: String
    },
    email: {
        type: String
    },
    password: {
        type: String
    }
});

const  User = module.exports = mongoose.model('User',UserSchema);

module.exports.registerUser = function (newUser,callback) {
    bcrypt.genSalt(10,function (err,salt) {

        bcrypt.hash(newUser.password,salt,function (err,hash) {

            if(err){
                console.log(err)
            }

            newUser.password = hash;
            newUser.save(callback);

        })

    })

}

module.exports.getUserByUserName = function(username, callback){
    const query = {username: username}
    User.findOne(query, callback);
}

module.exports.getUserById = function(id, callback){
    User.findById(id, callback);
}


module.exports.comparePassword = function (candidatePassword,hash,callback) {
    bcrypt.compare(candidatePassword,hash,function (err,isMathc) {
        if(err)
            throw err;
        callback(null,isMathc);
    })
}

