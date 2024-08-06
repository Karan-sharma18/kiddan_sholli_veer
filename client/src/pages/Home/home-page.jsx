import useAuth from "@/hooks/use-auth";
import HomeView from "./view/home-view";
import { useNavigate } from "react-router-dom";

const HomePage = () => {
  const { isLoggedIn } = useAuth();

  const navigate = useNavigate();
  if (!isLoggedIn) {
    navigate("/login");
    return;
  }
  
  return (
    <div className="w-[100%]">
      <HomeView />
    </div>
  );
};

export default HomePage;
