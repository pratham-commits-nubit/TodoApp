const nodemailer = require('nodemailer')

const transporter = nodemailer.createTransport({
    host:"smtp.gmail.com",
    port:587,
    auth:{
        user:"smithyehem@gmail.com",
        pass:"kcdz qgax cgkc mmkz"
    }
})

async function sendRecoveryEmail(userEmail,resetLink){
    const emailContent = await transporter.sendMail({
        from: '"Todoist Support Team" <support@todoist.com>',
        to: userEmail,
        subject: "Todoist: Password Reset Request",
        text: `Hello ${userEmail},
      
      Thank you for requesting a password reset. Please click the link below to reset your password. The link will expire in 10 minutes:
      
      ${resetLink}
      
      If you did not request a password reset, please disregard this email.
      
      Best regards,
      Todoist Support Team`,
        html: `<p>Hello ${userEmail},</p>
               <p>Thank you for requesting a password reset. Please click the link below to reset your password. The link will expire in 10 minutes:</p>
               <p><a href="${resetLink}">Reset Password</a></p>
               <p>If you did not request a password reset, please disregard this email.</p>
               <p>Best regards,</p>
               <p>Todoist Support Team</p>`
    });
    
}

module.exports = sendRecoveryEmail  