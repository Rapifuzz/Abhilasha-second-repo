"""
RAPIFuzz URLs.
"""
from django.contrib import admin
from django.urls import path
from fuzzer import views
from django.urls import include
from django.urls import re_path as url
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
 

description = """With the digital economy explosion the use of APIs (Application Program Interface) is growing. 
                 Be it a financial application or gaming, or weather or healthcare, APIs are being consumed. 
                 Applications are now fundamentally reliant on API, and surprisingly there is a very little focus on API security. 
                 'RAPIFUZZ- API Fuzzer'  is a Make-in-India initiative,to assist organizations to discover vulnerabilities 
                 in their APIs. RAPIFUZZ performs a series of security checks against your web APIs based on requirements laid out in 
                 the OWASP API Security TOP 2019. By leveraging the automated testing,our solution can test a web application or individual 
                 APIs and acts as a man-in-middle proxy, capturing traffic.We are focused on automation, and DevSecOps technologies to 
                 enhance and deploy the right technology in the organization."""
schema_view = get_schema_view(
   openapi.Info(
      title="RAPIFUZZ",
      default_version='v1.1.2',
      description=description,
      terms_of_service="",
      contact=openapi.Contact(email="subodh@rapifuzz.in"),
      license=openapi.License(name="GPL"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    url(r'^swagger$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),# API for getting RAPIFuzz swagger doc
    path('redoc', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),#API for getting RAPIFuzz redoc
    url(r'^swagger(?P<format>\.json|\.yaml|\.yml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),#API for getting different representations of swagger file.
    url(r'license/',include('license.urls')),#API for licence management
    path("",include('user_auth.urls')), # All user related APIs
    path("discovery/",include('discovery.urls')), # All discovery related APIs
    path("reports/",include('reports.urls')), # All reports related APIs
    path("individual/",include('individual.urls')),# All Individual app related api
    path('api/token',TokenObtainPairView().as_view()),# Generates auth token
    path('api/token/refresh',TokenRefreshView.as_view()), # Api for token refresh
   #  path('admin/', admin.site.urls), # API for viewing Django dashboard
    path('getmitmdata/<int:pid>/<int:sid>',views.get_mitm_data),# API to get data from MITM_AND_ADDRESPONSE table
    path('createproject',views.CreateProject.as_view()),#API for creation of new project
    path('createscan',views.CreateScan.as_view()), # API to schedule the scan
    path('projects',views.ProjectList.as_view()), #API that lists down all the projects
    path('scans',views.ScanList.as_view()),#API for listing down all the scans
    path("starttest/<int:pid>/<int:sid>",views.new_start_test),# API for starting the testing of APIs of a scan
    path('projects/<int:pid>',views.ProjectViewEditDelete.as_view()),#API for editing,getting and deleting a project
    path("bpendpointdata/<int:id>",views.bp_endpoint_data),#Api for all end points data 
   #  path("getappurl/<int:proj_id>",views.get_app_url),#API for getting the AUT url.
    path("logout",views.logout_token),#APi for logging out
    path("sendemail",views.email_test),#API for verifying an email
    path("smtpdetails",views.SMTPCreateView.as_view()),#API for saving new smtp details
    path("send/confirmemail",views.confirmation_email),#Api for email confirmation
    path("test/email",views.test_email),
    path("smtp/<int:id>",views.SMTPGetEditDeleteView.as_view()),
    path("cancel-scanning/<int:pid>/<int:sid>",views.cancel_scanning),#API for cancelling scanning of endpoints midway
    path("abort-testing/<int:pid>/<int:sid>",views.abort_testing),#API for aborting testing process in midway.
    path("mitmendpoint/<int:eid>",views.get_mitm_endpoint),
    path("total-data",views.total_data),
    path("small-card-data",views.small_card_data),
    path("vulnerable-paths",views.vulnerable_paths_card_data),
    path("getalltestcases/<int:sid>/<int:eid>",views.EndpointTestcaseListEid.as_view()),
    path("testcases/<int:pk>",views.EndpointTestcaseViewEditDelete.as_view()),
    path("addtestcase/<int:eid>",views.AddTestcaseAPIView.as_view()),
    path("addapi/<int:sid>",views.AddAPIView.as_view()),
    path("apis/<int:pk>",views.EditDeleteAndRetrieveAPIView.as_view()),
    path("hitapi",views.hit_api),
    path("delete-multiple-endpoints/<int:pid>/<int:sid>",views.delete_multiple_endpoints),
    path("delete-multiple-testcases/<int:pid>/<int:sid>",views.delete_multiple_testcases),
    path("update-jira-key/<int:pk>",views.jira_key_update),
    path("testcase-ids",views.get_all_testcases_id),
    path("at/<int:pid>/<int:sid>",views.get_API_type),
    path("csv/template",views.CreateCustomPayloadCSVFile.as_view()),
    path("csv/template/upload",views.UploadCustomPayloadsFileView.as_view()),
    path("custom-payloads",views.CustomPayloadAndRegexCreateView.as_view()),
    path("payload-group",views.CustomPayloadGroupView.as_view()), # GID add payload group
    path("payload-groups",views.CustomPayloadGroupListAPIView.as_view()),
    path("payload-group/<int:pk>",views.CustomPayloadGroupRetrieveUpdateDelete.as_view()),
    path("custom-payloads/<int:pk>",views.CustomPayloadAndRegexRUDView.as_view()),
    path("mids",views.get_possible_mids),
    path("activate-project/<int:pid>",views.activate_project),
    path("tech-type",views.get_distinct_technique),
    path("validate-token",views.validate_token),
    path("logfiledata",views.logfiledata),
    path("individual-log-data",views.individaul_log_data),
    path("downloadlogfile",views.download_log_file),
    path("false-report/<int:pk>",views.FalseReportRetrieveUpdateView.as_view()),
    path('reset-password',views.reset_password),# API for resetting the password
    path('testing-progress/<int:pid>/<int:sid>',views.thread_info),#for getting progress of the testing.
    path("download-archives",views.download_archives),
    path("http-custom-codes",views.UploadCustomHTTPCodesFileView.as_view()),
    path("httpcodes-group",views.CustomHTTPCodesGroupCreateAPIView.as_view()), # GID add payload group
    path("httpcodes-groups",views.CustomHTTPCodesGroupListAPIView.as_view()),
    path("httpcodes-group/<int:pk>",views.CustomHTTPCodesGroupRetrieveUpdateDelete.as_view()),
    path("download-encrypted-logs",views.get_encrypted_files),
    path("vulnerabilities/project",views.TotalVulnerabilitiesCountView.as_view()), # APIs for getting Dashboard card data
    path("vulnerabilities/individual",views.IndividualPieChartData.as_view()),
    path("dashboard-info",views.DashboardCardAPI.as_view()),# APIs 
    path("vulnerability-breakdown",views.VulnerablityBreakdown.as_view()),
    path("easily-exploitable-endpoints",views.EasilyExploitableEndpointView.as_view()),
    path("vulnerability-trends/<int:pid>",views.VulnerabilityTrendsView.as_view()),  # Vulnerability-trends chart
    path("vulnerability-details",views.VulnerabilityDetailsView.as_view()), #api for vulnerability details for project
    path("vulnerability-details-individual",views.VulnerabilityDetailsIndividualView.as_view()),#api for vulnerability details for single api
    path("vulnerable/endpoints",views.VulnerableEndpoints.as_view()),
    path("vulnerable-endpoints-details",views.VulnerableEndpointsDetailsView.as_view()),# to be implemented EndpointsDetailsView  VulnerableEpDetailsView
    path("vulnerable/endpoints/individual",views.IndividualVulnerableEndpointsView.as_view()),
    path("vulnerable-endpoints-details-individual",views.SingleAPIVulnerableEpDetailsView.as_view()),# to be implemented
    path("api-testing",views.testing_a_testcase),
    
]+ static(settings.MEDIA_URL,document_root_media=settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


if settings.DEBUG:
    urlpatterns.append(path("get-mitm-data-file/<int:pid>/<int:sid>", views.get_mitm_data_file))
    # path will be visible only in debug mode
