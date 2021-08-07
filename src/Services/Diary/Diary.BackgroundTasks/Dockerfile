#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/runtime:5.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["src/Services/Diary/Diary.BackgroundTasks/Diary.BackgroundTasks.csproj", "src/Services/Diary/Diary.BackgroundTasks/"]
RUN dotnet restore "src/Services/Diary/Diary.BackgroundTasks/Diary.BackgroundTasks.csproj"
COPY . .
WORKDIR "/src/src/Services/Diary/Diary.BackgroundTasks"
RUN dotnet build "Diary.BackgroundTasks.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Diary.BackgroundTasks.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Diary.BackgroundTasks.dll"]