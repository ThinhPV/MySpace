#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["src/Services/Identity/Identiity.Admin/Identiity.Admin.csproj", "src/Services/Identity/Identiity.Admin/"]
RUN dotnet restore "src/Services/Identity/Identiity.Admin/Identiity.Admin.csproj"
COPY . .
WORKDIR "/src/src/Services/Identity/Identiity.Admin"
RUN dotnet build "Identiity.Admin.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Identiity.Admin.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Identiity.Admin.dll"]