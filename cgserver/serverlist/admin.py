from django.contrib import admin

from .models import Client, ClientReport, UnknownReport

# Register your models here.

class ClientAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'client_id', 'display_name', 'created_at', )


class ClientReportAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'client', 'ip', 'version', 'created_at', )
    list_filter = ('client__client_id', 'ip', 'version', )


class UnknownReportAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'client_id', 'ip', 'version', 'created_at', )
    list_filter = ('client_id', 'ip', 'version', )


admin.site.register(Client, ClientAdmin)
admin.site.register(ClientReport, ClientReportAdmin)
admin.site.register(UnknownReport, UnknownReportAdmin)
