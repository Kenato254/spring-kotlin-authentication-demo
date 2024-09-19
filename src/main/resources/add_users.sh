#!/bin/bash

generate_random_date_of_birth() {
  current_year=$(date +%Y)
  min_year=$((current_year - 40))
  max_year=$((current_year - 20))

  random_year_within_age=$((RANDOM % (max_year - min_year + 1) + min_year))
  random_month=$(printf "%02d" $((RANDOM % 12 + 1)))
  random_day=$(printf "%02d" $((RANDOM % 28 + 1)))

  formatted_date_of_birth="$random_year_within_age-$random_month-$random_day"
  echo "$formatted_date_of_birth"
}

first_names=("John" "Jane" "Alex" "Emily" "Chris" "Katie" "Michael" "Sarah" "David" "Laura")
last_names=("Doe" "Smith" "Johnson" "Williams" "Brown" "Jones" "Miller" "Davis" "Garcia" "Rodriguez")

for i in $(seq 1 20); do
  first_name=${first_names[$RANDOM % ${#first_names[@]}]}
  last_name=${last_names[$RANDOM % ${#last_names[@]}]}
  email=$(echo "${first_name}${last_name}${i}@mail.com" | tr '[:upper:]' '[:lower:]')
  password="password${i}"
  date_of_birth=$(generate_random_date_of_birth)

  http POST http://localhost:8080/api/auth/register \
    firstName="$first_name" \
    lastName="$last_name" \
    email="$email" \
    password="$password" \
    dateOfBirth="$date_of_birth"

  sleep 1
done