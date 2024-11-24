const nodemailer = require('nodemailer')

const transporter = nodemailer.createTransport({
    host:"smtp.gmail.com",
    port:587,
    auth:{
        user:"smithyehem@gmail.com",
        pass:"kcdz qgax cgkc mmkz"
    }
})

async function sendEmail(userEmail,otp){
    const info = await transporter.sendMail({
        from: '"Todoist Support Team" <support@todoist.com>', // sender address
        to: userEmail, // user's email address
        subject: "Welcome to Todoist! Confirm Your Email", // Subject line
        text: `Hello ${userEmail},
    
    Thank you for signing up for Todoist! To complete your registration, please use the following One-Time Password (OTP) to verify your email address:
    
    OTP: ${otp}
    
    If you did not sign up for YourAppName, please disregard this email.
    
    Best regards,
    YourAppName Support Team`, // plain text body
        html: `<p>Hello ${userEmail},</p>
               <p>Thank you for signing up for <strong>Todoist</strong>! To complete your registration, please use the following One-Time Password (OTP) to verify your email address:</p>
               <h2>${otp}</h2>
               <p>If you did not sign up for Todoist, please disregard this email.</p>
               <p>Best regards,</p>
               <p>Todoist Support Team</p>`, // html body
    });
    
}

module.exports = sendEmail