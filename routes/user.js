var nodemailer = require('nodemailer');
var smtpTransport = require('nodemailer-smtp-transport');
var async = require('async');
var crypto = require('crypto');
var User = require('../models/user');
var secret = require('../secrets/secret');

module.exports = (app, passport) => {
    app.get('/', (req, res, next) => {
        res.render('index', { title: 'Index || Experts App' });
    });

    app.get('/signup', ( req, res ) => {
        var errors = req.flash('error');
        console.log(errors);
        res.render('user/signup', { title: 'Sign Up || Experts App', messages: errors, hasErrors: errors.length > 0 });
    });

    app.post('/signup', validate ,passport.authenticate('local.signup', {
        successRedirect: '/home',
        failureRedirect: '/signup',
        failureFlash: true
    }));
    app.get('/login', ( req, res ) => {
        var errors = req.flash('error');
        res.render('user/login', { title: 'Log In || Experts App', messages: errors, hasErrors: errors.length > 0 });
    });

    app.post('/login', loginValidate ,passport.authenticate('local.login', {
        successRedirect: '/home',
        failureRedirect: '/login',
        failureFlash: true
    }));

    app.get('/home', (req, res) => {
        res.render('home', {title: 'Home || Experts App', user: req.user});
    });

    app.get('/forgot', (req, res) => {
        var errors = req.flash('error');
        var info = req.flash('info');
        res.render('user/forgot', {title: 'Request for password reset', messages: errors, hasErrors: errors.length > 0,
        info: info, noErrors: info.length > 0});
    });

    app.post('/forgot', (req, res, next) => {
        async.waterfall([
            //Generate the token 
            function(callback){
                crypto.randomBytes(20, (err, buf) => {
                    var rand = buf.toString('hex');
                    callback(err, rand);
                });
            },
            // Check user is exist in database and set password token in database
            function(rand, callback) {
                User.findOne({'email': req.body.email}, (err, user) => {
                    if(!user){
                        req.flash('error', 'No Account Exist');
                        return res.redirect('/forgot');
                    }

                    user.passwordResetToken = rand;
                    user.passwordResetExpires = Date.now() + 60*60*1000;

                    user.save((err) => {
                        callback(err, rand, user)
                    })
                })
            },
            // this function is to sent email to the user
            function(rand, user, callback) {
                var smtpTransport = nodemailer.createTransport({
                    service: 'Gmail',
                    auth: {
                        user: secret.auth.user,
                        pass: secret.auth.pass
                    }
                });
                var mailOption = {
                    to: user.email,
                    from: 'Expert App' + '<' + secret.auth.user+'>',
                    subject: 'Expert App Password Reset Token',
                    text: 'You have requested for password reset token. \n\n' + 
                        'Please click on the link to complete process. \n\n'+
                        'http://localhost:3000/reset/'+rand+'\n\n'
                };
                smtpTransport.sendMail(mailOption, (err, response) => {
                    req.flash('info', 'A Password reset token has been sent to '+ user.email);
                    return callback(err, user);
                });
            }
        ], (err) => {
            if(err) {
                return next(err);
            }
            res.redirect('/forgot');
        });
    });
    // validation if the token is valid or not
    app.get('/reset/:token', (req, res) => {
        
                User.findOne({passwordResetToken: req.params.token, passwordResetExpires: {$gt: Date.now()}}, (err, user) => {
                    if(!user){
                        req.flash('error', 'Password reset token has expired or is invalid. Enter your email to get a new token.');
                        return res.redirect('/forgot');
                    }
                    var errors = req.flash('error');
                    var success = req.flash('success');
                    res.render('user/reset', {title: 'Reset Your password', messages: errors, hasErrors: errors.length > 0, success: success, noErrors: success.length > 0});
                });
            });
        
            app.post('/reset/:token', (req, res) => {
                async.waterfall([
                    function(callback){
                        User.findOne({passwordResetToken: req.params.token, passwordResetExpires: {$gt: Date.now()}}, (err, user) => {
                            if(!user){
                                req.flash('error', 'Password reset token has expired or is invalid. Enter your email to get a new token.');
                                return res.redirect('/forgot');
                            }
        
                            req.checkBody('password', 'Password is required').notEmpty();
                            req.checkBody('password', 'Password not be less than 6 characters').isLength({min: 6});
                            req.checkBody('password', 'Password must have atleast 1 Number and 1 Character').matches(/^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9]{6,}$/, "i");
        
                            var errors = req.validationErrors();
                            if(req.body.password == req.body.cpassword){
                                if(errors){
                                    var messages = [];
                                    errors.forEach((error) => {
                                        messages.push(error.msg)
                                    })
                                    var errors = req.flash('error');
                                    res.redirect('/reset/' + req.params.token);
                                } else {
                                    user.password = user.encryptPassword(req.body.password);
                                    user.passwordResetToken = undefined;
                                    user.passwordResetExpires = undefined;
                                    user.save((err) => {
                                        req.flash('Success', 'Your Password has been changed');
                                        callback(err, user);
                                    });
                                }
                            } else {
                                req.flash('error', 'Password and Confirm Password are not equal.');
                                res.redirect('/reset/' + req.params.token);
                            }
        
                            // res.render('user/reset', {title: 'Reset Your password', messages: errors, hasErrors: errors.length > 0});
                        });
                    },
                    function(user, callback) {
                        var smtpTransport = nodemailer.createTransport({
                            service: 'Gmail',
                            auth: {
                                user: secret.auth.user,
                                pass: secret.auth.pass
                            }
                        });
                        var mailOptions = {
                            to: user.email,
                            from: 'Expert App'+'<'+secret.auth.user+'>',
                            subject: 'Your password is changed',
                            text: 'This is a confirmation that your password is changed ' + user.email
                        };
        
                        smtpTransport.sendMail(mailOptions, (err, res) => {
                            callback(err, user);
        
                            var error = req.flash('error');
                            var success = req.flash('success');
        
                            res.render('user/reset', {title: 'Reset Your password', messages: error, hasErrors: error.length > 0, success: success, noErrors: success.length > 0});
        
                        });
                    }
                ]);
            });
            app.get('/logout', (req, res) => {
                req.logout();
                res.redirect('/');
            });
            app.get('/addPatient', (req, res) => {
                res.render('addPatient', {title: 'Add new Patient || Experts App', user: req.user});
            });
            app.get('/viewPatient', (req, res) => {
                res.render('viewPatient', {title: 'View Patient || Experts App'});
            });
            app.get('/reports', (req, res) => {
                res.render('reports', {title: 'Reports || Experts App'});
            });
            app.get('/profile', (req, res) => {
                res.render('profile', {title: 'Profile || Experts App'})
            });
};


function validate(req, res, next) {
    req.checkBody('fullname', 'Full Name is Required').notEmpty();
    req.checkBody('fullname', 'Fullname not be Less than 5 Charaters').isLength({min: 5});
    req.checkBody('email', 'Email is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is required').notEmpty();
    req.checkBody('password', 'Password not be less than 6 characters').isLength({min: 6});
    req.checkBody('password', 'Password must have atleast 1 Number and 1 Character').matches(/^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9]{6,}$/, "i");

    var errors = req.validationErrors();

    if(errors) {
        var messages = [];
        errors.forEach((error) => {
            messages.push(error.msg);            
        });

        req.flash('error', messages);
        res.redirect('/signup');
    } else {
        return next();
    }
}

function loginValidate(req, res, next) {
    req.checkBody('email', 'Email is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is required').notEmpty();
    req.checkBody('password', 'Password not be less than 6 characters').isLength({min: 6});
    req.checkBody('password', 'Password must have atleast 1 Number and 1 Character').matches(/^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9]{6,}$/, "i");

    var loginErrors = req.validationErrors();

    if(loginErrors) {
        var messages = [];
        loginErrors.forEach((error) => {
            messages.push(error.msg);            
        });

        req.flash('error', messages);
        res.redirect('/login');
    } else {
        return next();
    }
}
