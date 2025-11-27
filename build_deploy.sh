./gradlew clean bootjar
docker build -t member:1.0.0 .
minikube image load member:1.0.0
kubectl apply -f ./k8s/member-service-open.yaml
kubectl get pod -o wide