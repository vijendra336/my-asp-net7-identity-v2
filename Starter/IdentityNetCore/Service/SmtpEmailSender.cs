using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace IdentityNetCore.Service
{
    public class SmtpEmailSender : IEmailService
    {
        private readonly IOptions<SmtpOptions> options;

        public SmtpEmailSender(IOptions<SmtpOptions> options)
        {
            this.options = options;
        }
        public async Task SendEmailAsync(string fromAddress, string toAddress, string subject, string message)
        {
           var mailMessage= new MailMessage(fromAddress, toAddress, subject, message);

            using (var client = new SmtpClient(options.Value.Host, options.Value.Port)
            {
                Credentials = new NetworkCredential(options.Value.Username, options.Value.Password)
            })
            {
            }
        }
    }
}
