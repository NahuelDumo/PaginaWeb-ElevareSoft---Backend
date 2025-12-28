const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_PORT == 465, // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

async function sendResetPasswordEmail(to, token) {
    const resetUrl = `${process.env.FRONTEND_URL}?token=${token}`;

    const mailOptions = {
        from: `"Elevare Soft" <${process.env.SMTP_USER}>`,
        to: to,
        subject: 'Recuperación de Contraseña - Elevare Soft',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                <h2 style="color: #333; text-align: center;">Recuperación de Contraseña</h2>
                <p>Hola,</p>
                <p>Has solicitado restablecer tu contraseña para acceder al Portal de Administración de Elevare Soft. Haz clic en el siguiente botón para continuar:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetUrl}" style="background-color: #007bff; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">Restablecer Contraseña</a>
                </div>
                <p>Este enlace expirará en 1 hora.</p>
                <p>Si no solicitaste este cambio, puedes ignorar este correo.</p>
                <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 12px; color: #888; text-align: center;">Elevare Soft - Sistema de Administración</p>
            </div>
        `,
    };

    return transporter.sendMail(mailOptions);
}

module.exports = {
    sendResetPasswordEmail,
};
