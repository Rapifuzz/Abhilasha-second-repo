"""
Testing  user_auth 
"""

from .models import User
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from uuid import uuid4


def get_user_token(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserAPITests(APITestCase):
    def setUp(self):
        
        self.user = User.objects.create_superuser(username='testuser',name="testuser",email = "testuser1@mail.com",password='testuser',uu_id = str(uuid4()).replace('-',''),is_active = True,email_verified = True,role = "ROLE_ADMIN")

        token = get_user_token(self.user)
        self.auth = {"Authorization":"Bearer "+token.get('access',None)}

    # def test_get_user_list(self):
    #     response = self.client.get('/users')
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_user(self):
        # Set the Authorization header with the Token
        self.client.credentials(HTTP_AUTHORIZATION=self.auth['Authorization'])
        
        user = {
            "is_active": True,
            "email_verified": True,
            "uu_id":str(uuid4()).replace('-',''), # add uuid to the new user 
            "role":"ROLE_USER",
            "name": "testuser",
            "password": "Rapifuzz!1",
            "email": "testuser@mail.com",
            "permissions":{
                "projects":{
                    "edit":True,
                    "pname":""
                },
                "scans":{
                    "edit":True,
                    "add":True,
                    "view":True
                },
                "reports":{
                    "view":True,
                    "rpdf":True,
                    "rexcel":True
                }
            }
        }

        response = self.client.post('/users',user,format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(User.objects.last().name, 'testuser')

    def test_get_user_detail(self):
        # Set the Authorization header with the Token
        self.client.credentials(HTTP_AUTHORIZATION=self.auth['Authorization'])
        
        response = self.client.get('/users/{}'.format(self.user.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser')

    def test_update_user(self):
        data = {'name': 'updateduser'}
        # Set the Authorization header with the Token
        self.client.credentials(HTTP_AUTHORIZATION=self.auth['Authorization'])
        
        response = self.client.put('/users/{}'.format(self.user.id), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.get(id=self.user.id).name, 'updateduser')

    # def test_delete_user(self):
    #     response = self.client.delete('/users/{}'.format(self.user.id))
    #     self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
    #     self.assertEqual(User.objects.count(), 0)