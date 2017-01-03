using Orchard.Azure.Authentication.Models;
using Orchard.ContentManagement;
using Orchard.ContentManagement.Handlers;
using Orchard.Localization;

namespace Orchard.Azure.Authentication.Handlers {
    public class AzureSettingsPartHandler : ContentHandler {
        public AzureSettingsPartHandler() {
            T = NullLocalizer.Instance;
            Filters.Add(new ActivatingFilter<AzureSettingsPart>("Site"));
            Filters.Add(new TemplateFilterForPart<AzureSettingsPart>("AzureSettings", "Parts/AzureSettings", "Azure Authentication"));
        }

        public Localizer T { get; set; }

        protected override void GetItemMetadata(GetContentItemMetadataContext context) {
            if (context.ContentItem.ContentType != "Site") return;

            base.GetItemMetadata(context);
            context.Metadata.EditorGroupInfo.Add(new GroupInfo(T("Azure Authentication")));
        }
    }
}