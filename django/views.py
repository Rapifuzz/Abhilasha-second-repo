class OrganizationView(APIView):
    pagination_class = CustomPagination

    @staticmethod
    def get_object(pk):
        try:
            return Organization.objects.get(pk=pk)
        except Organization.DoesNotExist:
            raise Http404

    def get(self, request, pk=None):
        if pk:
            org = self.get_object(pk=pk)
            serializer = OrganizationSerializer(org)
            return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)
        else:
            orgs = Organization.objects.all()
            paginator = self.pagination_class(page_size=12)
            result_page = paginator.paginate_queryset(orgs, request)
            serializer = OrganizationListSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        serializer = OrganizationSerializer(data=request.data, user=request.user)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "Organization created successfully."},
                            status=status.HTTP_201_CREATED)
        return Response({'success': False, 'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        org = self.get_object(pk=pk)
        serializer = OrganizationSerializer(org, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "Organization updated successfully."
                             }, status=status.HTTP_200_OK)
        return Response({'success': False, 'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        organization = self.get_object(pk)
        username = request.user.username
        password = request.data.get("password", None)
        if not password:
            raise ValidationError('Password is missing.')
        serializer = UserLoginSerializer(data={'username': username, 'password': password})
        if serializer.is_valid():
            organization.delete()
            return Response({'success': True, 'message': "Organization deleted successfully."},
                            status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'success': False, 'message': serializer.errors}, status=status.HTTP_403_FORBIDDEN)
