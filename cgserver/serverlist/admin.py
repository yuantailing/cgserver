from django.contrib import admin

from .models import AccessLog, Client, ClientReport, Employee, FtpPerm, GithubUser, UnknownReport

# Register your models here.

class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'client', 'ip', 'target', 'param', 'created_at', )
    list_filter = ('user', 'client', 'target', )
    readonly_fields = ('user', 'client', 'ip', 'target', 'param', 'info', )


class ClientAdmin(admin.ModelAdmin):
    list_display = ('id', 'client_id', 'display_name', 'priority', 'created_at', )
    list_filter = ('priority', )


class ClientReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'client', 'ip', 'version', 'dns_success', 'created_at', )
    list_filter = ('client__client_id', 'ip', 'version', 'dns_success', )


class EmployeeAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj=None):
        if obj:
            return ('user', ) + self.readonly_fields
        return self.readonly_fields

    def user_email(inst):
        return inst.user.email

    def password_is_set(inst):
        return inst.shadow_password not in (None, '') and inst.nt_password_hash not in (None, '')

    list_display = ('user', user_email, 'can_access', 'staff_number', 'vpn_privileged', 'vpn_privileged_until', 'ftp_insecure', )
    list_filter = ('can_access', 'vpn_privileged', 'ftp_insecure', )
    exclude = ('nt_password_hash', 'shadow_password', )
    readonly_fields = (user_email, 'staff_number', password_is_set, 'password_updated_at', )


class FtpPermAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'path', 'isdir', 'permission', )
    list_filter = ('user', 'path', 'isdir', 'permission', )


class GithubUserAdmin(admin.ModelAdmin):
    def user_username(inst):
        return inst.user.username

    list_display = ('id', user_username, 'github_id', 'github_login', 'github_email', )
    readonly_fields = ('github_id', )


class UnknownReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'client_id', 'ip', 'version', 'created_at', )
    list_filter = ('client_id', 'ip', 'version', )


admin.site.register(AccessLog, AccessLogAdmin)
admin.site.register(Client, ClientAdmin)
admin.site.register(ClientReport, ClientReportAdmin)
admin.site.register(Employee, EmployeeAdmin)
admin.site.register(FtpPerm, FtpPermAdmin)
admin.site.register(GithubUser, GithubUserAdmin)
admin.site.register(UnknownReport, UnknownReportAdmin)
