using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WeChatWEB.Startup))]
namespace WeChatWEB
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
